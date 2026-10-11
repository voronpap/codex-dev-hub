#define PY_SSIZE_T_CLEAN
#define WIN32_LEAN_AND_MEAN
#include <Python.h>
#include <windows.h>
#include <wchar.h>

#define DEVFABRIC_LOAD_FLAGS \
    (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)

typedef struct {
    const wchar_t *name;
    const char *label;
    HMODULE handle;
} DevFabricLibrary;

static DevFabricLibrary libraries[] = {
    {L"libffi-8.dll", "libffi-8.dll", NULL},
    {L"libcrypto-3.dll", "libcrypto-3.dll", NULL},
    {L"libssl-3.dll", "libssl-3.dll", NULL},
};
static SRWLOCK loader_lock = SRWLOCK_INIT;
static int loader_active = 0;

static int
same_file_identity(HANDLE expected, HANDLE observed, DWORD *failure_error)
{
    BY_HANDLE_FILE_INFORMATION left;
    BY_HANDLE_FILE_INFORMATION right;
    if (!GetFileInformationByHandle(expected, &left)) {
        *failure_error = GetLastError();
        return 0;
    }
    if (!GetFileInformationByHandle(observed, &right)) {
        *failure_error = GetLastError();
        return 0;
    }
    if (left.dwVolumeSerialNumber != right.dwVolumeSerialNumber ||
        left.nFileIndexHigh != right.nFileIndexHigh ||
        left.nFileIndexLow != right.nFileIndexLow) {
        *failure_error = ERROR_ACCESS_DENIED;
        return 0;
    }
    return 1;
}

static HANDLE
open_plain_file(const wchar_t *path)
{
    HANDLE handle = CreateFileW(
        path,
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (handle == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))) {
        DWORD error = GetLastError();
        CloseHandle(handle);
        SetLastError(error);
        return INVALID_HANDLE_VALUE;
    }
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(handle);
        SetLastError(ERROR_REPARSE_TAG_INVALID);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

static HANDLE
open_plain_directory(const wchar_t *path)
{
    HANDLE handle = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (handle == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))) {
        DWORD error = GetLastError();
        CloseHandle(handle);
        SetLastError(error);
        return INVALID_HANDLE_VALUE;
    }
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        CloseHandle(handle);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

static int
module_directory(wchar_t *directory, DWORD capacity)
{
    HMODULE self = NULL;
    wchar_t helper_path[MAX_PATH];
    wchar_t python_path[MAX_PATH];
    wchar_t *helper_separator;
    wchar_t *python_separator;
    DWORD helper_length;
    DWORD python_length;

    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)(const void *)&loader_lock,
            &self)) {
        return 0;
    }
    helper_length = GetModuleFileNameW(self, helper_path, MAX_PATH);
    if (helper_length == 0) {
        return 0;
    }
    if (helper_length >= MAX_PATH) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    python_length = GetModuleFileNameW(NULL, python_path, MAX_PATH);
    if (python_length == 0) {
        return 0;
    }
    if (python_length >= MAX_PATH) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    helper_separator = wcsrchr(helper_path, L'\\');
    python_separator = wcsrchr(python_path, L'\\');
    if (helper_separator == NULL || python_separator == NULL) {
        SetLastError(ERROR_BAD_PATHNAME);
        return 0;
    }
    *helper_separator = L'\0';
    *python_separator = L'\0';
    if (_wcsicmp(helper_path, python_path) != 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }
    if (wcslen(helper_path) + 1 > capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    wcscpy_s(directory, capacity, helper_path);
    return 1;
}

static int
load_one(
    DevFabricLibrary *library,
    const wchar_t *directory,
    const char **failure_stage)
{
    wchar_t expected_path[MAX_PATH];
    wchar_t loaded_path[MAX_PATH];
    HANDLE expected_file = INVALID_HANDLE_VALUE;
    HANDLE loaded_file = INVALID_HANDLE_VALUE;
    HMODULE loaded = NULL;
    DWORD loaded_length;
    DWORD failure_error = ERROR_SUCCESS;
    int result = 0;

    *failure_stage = "dependency_preopen";
    if (swprintf_s(expected_path, MAX_PATH, L"%ls\\%ls", directory, library->name) < 0) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    expected_file = open_plain_file(expected_path);
    if (expected_file == INVALID_HANDLE_VALUE) {
        *failure_stage = "dependency_preopen";
        return 0;
    }
    loaded = LoadLibraryExW(expected_path, NULL, DEVFABRIC_LOAD_FLAGS);
    if (loaded == NULL) {
        *failure_stage = "dependency_load";
        failure_error = GetLastError();
        goto done;
    }
    loaded_length = GetModuleFileNameW(loaded, loaded_path, MAX_PATH);
    if (loaded_length == 0) {
        *failure_stage = "loaded_path_query";
        failure_error = GetLastError();
        goto done;
    }
    if (loaded_length >= MAX_PATH) {
        *failure_stage = "loaded_path_query";
        failure_error = ERROR_INSUFFICIENT_BUFFER;
        goto done;
    }
    loaded_file = open_plain_file(loaded_path);
    if (loaded_file == INVALID_HANDLE_VALUE) {
        *failure_stage = "loaded_file_reopen";
        failure_error = GetLastError();
        goto done;
    }
    if (_wcsicmp(expected_path, loaded_path) != 0) {
        *failure_stage = "file_identity_compare";
        failure_error = ERROR_ACCESS_DENIED;
        goto done;
    }
    if (!same_file_identity(expected_file, loaded_file, &failure_error)) {
        *failure_stage = "file_identity_compare";
        goto done;
    }
    library->handle = loaded;
    loaded = NULL;
    result = 1;

done:
    if (loaded_file != INVALID_HANDLE_VALUE) {
        CloseHandle(loaded_file);
    }
    if (loaded != NULL) {
        FreeLibrary(loaded);
    }
    CloseHandle(expected_file);
    if (!result) {
        SetLastError(failure_error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : failure_error);
    }
    return result;
}

static PyObject *
raise_activation_error(const char *stage, const char *dependency, DWORD error)
{
    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;
    PyObject *stage_value = NULL;
    PyObject *dependency_value = NULL;

    PyErr_SetFromWindowsErr((int)error);
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);
    if (value == NULL) {
        Py_XDECREF(type);
        Py_XDECREF(traceback);
        return NULL;
    }
    stage_value = PyUnicode_FromString(stage);
    dependency_value = dependency == NULL ? Py_NewRef(Py_None) : PyUnicode_FromString(dependency);
    if (stage_value == NULL || dependency_value == NULL ||
        PyObject_SetAttrString(value, "devfabric_failure_stage", stage_value) < 0 ||
        PyObject_SetAttrString(value, "devfabric_failure_dependency", dependency_value) < 0) {
        Py_XDECREF(stage_value);
        Py_XDECREF(dependency_value);
        Py_XDECREF(type);
        Py_XDECREF(value);
        Py_XDECREF(traceback);
        return NULL;
    }
    Py_DECREF(stage_value);
    Py_DECREF(dependency_value);
    PyErr_Restore(type, value, traceback);
    return NULL;
}

static PyObject *
activation_result(void)
{
    PyObject *result = PyTuple_New(3);
    Py_ssize_t index;
    if (result == NULL) {
        return NULL;
    }
    for (index = 0; index < 3; ++index) {
        PyObject *item = PyUnicode_FromWideChar(libraries[index].name, -1);
        if (item == NULL) {
            Py_DECREF(result);
            return NULL;
        }
        PyTuple_SET_ITEM(result, index, item);
    }
    return result;
}

static PyObject *
activate(PyObject *self, PyObject *unused)
{
    wchar_t directory[MAX_PATH];
    size_t index;
    size_t loaded_count = 0;
    DWORD error = ERROR_SUCCESS;
    const char *failure_stage = "module_interpreter_sibling_identity";
    const char *failure_dependency = NULL;
    HANDLE directory_handle = INVALID_HANDLE_VALUE;
    PyObject *result = NULL;
    (void)self;
    (void)unused;

    AcquireSRWLockExclusive(&loader_lock);
    if (loader_active) {
        result = activation_result();
        ReleaseSRWLockExclusive(&loader_lock);
        return result;
    }
    if (!module_directory(directory, MAX_PATH)) {
        error = GetLastError();
        goto failed;
    }
    directory_handle = open_plain_directory(directory);
    if (directory_handle == INVALID_HANDLE_VALUE) {
        failure_stage = "directory_open_validation";
        error = GetLastError();
        goto failed;
    }
    for (index = 0; index < 3; ++index) {
        failure_dependency = libraries[index].label;
        if (!load_one(&libraries[index], directory, &failure_stage)) {
            error = GetLastError();
            goto failed;
        }
        ++loaded_count;
    }
    loader_active = 1;
    result = activation_result();
    CloseHandle(directory_handle);
    ReleaseSRWLockExclusive(&loader_lock);
    return result;

failed:
    if (directory_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(directory_handle);
    }
    while (loaded_count > 0) {
        --loaded_count;
        FreeLibrary(libraries[loaded_count].handle);
        libraries[loaded_count].handle = NULL;
    }
    ReleaseSRWLockExclusive(&loader_lock);
    return raise_activation_error(failure_stage, failure_dependency, error);
}

static PyMethodDef methods[] = {
    {"activate", (PyCFunction)activate, METH_NOARGS,
     "Load the fixed DevFabric dependency set from the interpreter sibling directory."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_devfabric_native_loader",
    NULL,
    -1,
    methods,
};

PyMODINIT_FUNC
PyInit__devfabric_native_loader(void)
{
    return PyModule_Create(&module);
}
