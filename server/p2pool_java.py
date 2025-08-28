import os
import ctypes
import platform
import sys

# --- Configuration ---
# In "dev" mode, we'll use a local JDK.
# In "prod" mode (when packaged with PyInstaller), we'll look for the JDK
# in a directory relative to the executable.

if hasattr(sys, '_MEIPASS'):
    # PyInstaller creates a temp folder and stores path in _MEIPASS
    base_path = sys._MEIPASS
else:
    base_path = os.path.abspath("tools")
JDK_HOME = os.path.join(base_path, "jdk-24.0.2")


# --- Platform-specific JVM path ---
if platform.system() == "Windows":
    JVM_DLL = os.path.join(JDK_HOME, "bin", "server", "jvm.dll")
elif platform.system() == "Darwin": # macOS
    JVM_DLL = os.path.join(JDK_HOME, "lib", "server", "libjvm.dylib")
else: # Linux
    JVM_DLL = os.path.join(JDK_HOME, "lib", "server", "libjvm.so")

if not os.path.exists(JVM_DLL):
    raise FileNotFoundError(f"Could not find JVM at: {JVM_DLL}\nPlease check your JDK_HOME path.")

# --- FIX: Use WinDLL on Windows for the __stdcall calling convention ---
# JNI functions on Windows use the __stdcall calling convention. Using CDLL
# (which defaults to cdecl) will corrupt the stack and cause a crash.
try:
    if platform.system() == "Windows":
        jvm = ctypes.WinDLL(JVM_DLL)
    else:
        jvm = ctypes.CDLL(JVM_DLL)
except OSError as e:
    raise OSError(f"Failed to load JVM. Error: {e}")

print("✅ JVM library loaded successfully.")


# --- JNI Type Definitions ---

# --- FIX: Define a platform-specific function prototype for JNI calls ---
# This uses WINFUNCTYPE (stdcall) on Windows and CFUNCTYPE (cdecl) on other platforms.
if platform.system() == "Windows":
    JNI_FUNCTYPE = ctypes.WINFUNCTYPE
else:
    JNI_FUNCTYPE = ctypes.CFUNCTYPE


# Forward declare JNIEnv
class JNIEnv(ctypes.Structure): pass
JNIEnv_p = ctypes.POINTER(JNIEnv)

class JavaVMOption(ctypes.Structure):
    _fields_ = [("optionString", ctypes.c_char_p),
                ("extraInfo", ctypes.c_void_p)]

class JavaVMInitArgs(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_int),
        ("nOptions", ctypes.c_int),
        ("options", ctypes.POINTER(JavaVMOption)),
        ("ignoreUnrecognized", ctypes.c_int)
    ]

class JavaVM(ctypes.Structure): pass
JavaVM_p = ctypes.POINTER(JavaVM)

# The jvalue union is used to pass arguments to Java methods
# when using the 'A' (argument array) versions of the call functions.
class jvalue(ctypes.Union):
    _fields_ = [
        ("z", ctypes.c_bool),
        ("b", ctypes.c_byte),
        # FIX: jchar is a 16-bit unsigned type, c_ushort is a reliable equivalent.
        # c_wchar's size is platform-dependent.
        ("c", ctypes.c_ushort),
        ("s", ctypes.c_short),
        ("i", ctypes.c_int),
        ("j", ctypes.c_longlong),
        ("f", ctypes.c_float),
        ("d", ctypes.c_double),
        ("l", ctypes.c_void_p), # 'l' is for jobject
    ]

# --- JNI Function Pointer Table Definition ---
# This structure must be a complete and accurate representation of the JNI
# function table. All CFUNCTYPE instances are replaced with the platform-aware
# JNI_FUNCTYPE to ensure the correct calling convention is used.
class JNINativeInterface(ctypes.Structure):
    _fields_ = [
        ("reserved0", ctypes.c_void_p),
        ("reserved1", ctypes.c_void_p),
        ("reserved2", ctypes.c_void_p),
        ("reserved3", ctypes.c_void_p),
        ("GetVersion", JNI_FUNCTYPE(ctypes.c_int, JNIEnv_p)),
        ("DefineClass", ctypes.c_void_p),
        ("FindClass", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p, ctypes.c_char_p)),
        ("FromReflectedMethod", ctypes.c_void_p),
        ("FromReflectedField", ctypes.c_void_p),
        ("ToReflectedMethod", ctypes.c_void_p),
        ("GetSuperclass", ctypes.c_void_p),
        ("IsAssignableFrom", ctypes.c_void_p),
        ("ToReflectedField", ctypes.c_void_p),
        ("Throw", ctypes.c_void_p),
        ("ThrowNew", ctypes.c_void_p),
        ("ExceptionOccurred", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p)),
        ("ExceptionDescribe", JNI_FUNCTYPE(None, JNIEnv_p)),
        ("ExceptionClear", JNI_FUNCTYPE(None, JNIEnv_p)),
        ("FatalError", ctypes.c_void_p),
        ("PushLocalFrame", ctypes.c_void_p),
        ("PopLocalFrame", ctypes.c_void_p),
        ("NewGlobalRef", ctypes.c_void_p),
        ("DeleteGlobalRef", ctypes.c_void_p),
        ("DeleteLocalRef", JNI_FUNCTYPE(None, JNIEnv_p, ctypes.c_void_p)),
        ("IsSameObject", ctypes.c_void_p),
        ("NewLocalRef", ctypes.c_void_p),
        ("EnsureLocalCapacity", ctypes.c_void_p),
        ("AllocObject", ctypes.c_void_p),
        ("NewObject", ctypes.c_void_p),
        ("NewObjectV", ctypes.c_void_p),
        ("NewObjectA", ctypes.c_void_p),
        ("GetObjectClass", ctypes.c_void_p),
        ("IsInstanceOf", ctypes.c_void_p),
        ("GetMethodID", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)),
        ("CallObjectMethod", ctypes.c_void_p),
        ("CallObjectMethodV", ctypes.c_void_p),
        ("CallObjectMethodA", ctypes.c_void_p),
        ("CallBooleanMethod", ctypes.c_void_p),
        ("CallBooleanMethodV", ctypes.c_void_p),
        ("CallBooleanMethodA", ctypes.c_void_p),
        ("CallByteMethod", ctypes.c_void_p),
        ("CallByteMethodV", ctypes.c_void_p),
        ("CallByteMethodA", ctypes.c_void_p),
        ("CallCharMethod", ctypes.c_void_p),
        ("CallCharMethodV", ctypes.c_void_p),
        ("CallCharMethodA", ctypes.c_void_p),
        ("CallShortMethod", ctypes.c_void_p),
        ("CallShortMethodV", ctypes.c_void_p),
        ("CallShortMethodA", ctypes.c_void_p),
        ("CallIntMethod", ctypes.c_void_p),
        ("CallIntMethodV", ctypes.c_void_p),
        ("CallIntMethodA", ctypes.c_void_p),
        ("CallLongMethod", ctypes.c_void_p),
        ("CallLongMethodV", ctypes.c_void_p),
        ("CallLongMethodA", ctypes.c_void_p),
        ("CallFloatMethod", ctypes.c_void_p),
        ("CallFloatMethodV", ctypes.c_void_p),
        ("CallFloatMethodA", ctypes.c_void_p),
        ("CallDoubleMethod", ctypes.c_void_p),
        ("CallDoubleMethodV", ctypes.c_void_p),
        ("CallDoubleMethodA", ctypes.c_void_p),
        ("CallVoidMethod", ctypes.c_void_p),
        ("CallVoidMethodV", ctypes.c_void_p),
        ("CallVoidMethodA", ctypes.c_void_p),
        ("CallNonvirtualObjectMethod", ctypes.c_void_p),
        ("CallNonvirtualObjectMethodV", ctypes.c_void_p),
        ("CallNonvirtualObjectMethodA", ctypes.c_void_p),
        ("CallNonvirtualBooleanMethod", ctypes.c_void_p),
        ("CallNonvirtualBooleanMethodV", ctypes.c_void_p),
        ("CallNonvirtualBooleanMethodA", ctypes.c_void_p),
        ("CallNonvirtualByteMethod", ctypes.c_void_p),
        ("CallNonvirtualByteMethodV", ctypes.c_void_p),
        ("CallNonvirtualByteMethodA", ctypes.c_void_p),
        ("CallNonvirtualCharMethod", ctypes.c_void_p),
        ("CallNonvirtualCharMethodV", ctypes.c_void_p),
        ("CallNonvirtualCharMethodA", ctypes.c_void_p),
        ("CallNonvirtualShortMethod", ctypes.c_void_p),
        ("CallNonvirtualShortMethodV", ctypes.c_void_p),
        ("CallNonvirtualShortMethodA", ctypes.c_void_p),
        ("CallNonvirtualIntMethod", ctypes.c_void_p),
        ("CallNonvirtualIntMethodV", ctypes.c_void_p),
        ("CallNonvirtualIntMethodA", ctypes.c_void_p),
        ("CallNonvirtualLongMethod", ctypes.c_void_p),
        ("CallNonvirtualLongMethodV", ctypes.c_void_p),
        ("CallNonvirtualLongMethodA", ctypes.c_void_p),
        ("CallNonvirtualFloatMethod", ctypes.c_void_p),
        ("CallNonvirtualFloatMethodV", ctypes.c_void_p),
        ("CallNonvirtualFloatMethodA", ctypes.c_void_p),
        ("CallNonvirtualDoubleMethod", ctypes.c_void_p),
        ("CallNonvirtualDoubleMethodV", ctypes.c_void_p),
        ("CallNonvirtualDoubleMethodA", ctypes.c_void_p),
        ("CallNonvirtualVoidMethod", ctypes.c_void_p),
        ("CallNonvirtualVoidMethodV", ctypes.c_void_p),
        ("CallNonvirtualVoidMethodA", ctypes.c_void_p),
        ("GetFieldID", ctypes.c_void_p),
        ("GetObjectField", ctypes.c_void_p),
        ("GetBooleanField", ctypes.c_void_p),
        ("GetByteField", ctypes.c_void_p),
        ("GetCharField", ctypes.c_void_p),
        ("GetShortField", ctypes.c_void_p),
        ("GetIntField", ctypes.c_void_p),
        ("GetLongField", ctypes.c_void_p),
        ("GetFloatField", ctypes.c_void_p),
        ("GetDoubleField", ctypes.c_void_p),
        ("SetObjectField", ctypes.c_void_p),
        ("SetBooleanField", ctypes.c_void_p),
        ("SetByteField", ctypes.c_void_p),
        ("SetCharField", ctypes.c_void_p),
        ("SetShortField", ctypes.c_void_p),
        ("SetIntField", ctypes.c_void_p),
        ("SetLongField", ctypes.c_void_p),
        ("SetFloatField", ctypes.c_void_p),
        ("SetDoubleField", ctypes.c_void_p),
        ("GetStaticMethodID", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)),
        ("CallStaticObjectMethod", ctypes.c_void_p),
        ("CallStaticObjectMethodV", ctypes.c_void_p),
        ("CallStaticObjectMethodA", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(jvalue))),
        ("CallStaticBooleanMethod", ctypes.c_void_p),
        ("CallStaticBooleanMethodV", ctypes.c_void_p),
        ("CallStaticBooleanMethodA", ctypes.c_void_p),
        ("CallStaticByteMethod", ctypes.c_void_p),
        ("CallStaticByteMethodV", ctypes.c_void_p),
        ("CallStaticByteMethodA", ctypes.c_void_p),
        ("CallStaticCharMethod", ctypes.c_void_p),
        ("CallStaticCharMethodV", ctypes.c_void_p),
        ("CallStaticCharMethodA", ctypes.c_void_p),
        ("CallStaticShortMethod", ctypes.c_void_p),
        ("CallStaticShortMethodV", ctypes.c_void_p),
        ("CallStaticShortMethodA", ctypes.c_void_p),
        ("CallStaticIntMethod", ctypes.c_void_p),
        ("CallStaticIntMethodV", ctypes.c_void_p),
        ("CallStaticIntMethodA", ctypes.c_void_p),
        ("CallStaticLongMethod", ctypes.c_void_p),
        ("CallStaticLongMethodV", ctypes.c_void_p),
        ("CallStaticLongMethodA", ctypes.c_void_p),
        ("CallStaticFloatMethod", ctypes.c_void_p),
        ("CallStaticFloatMethodV", ctypes.c_void_p),
        ("CallStaticFloatMethodA", ctypes.c_void_p),
        ("CallStaticDoubleMethod", ctypes.c_void_p),
        ("CallStaticDoubleMethodV", ctypes.c_void_p),
        ("CallStaticDoubleMethodA", ctypes.c_void_p),
        ("CallStaticVoidMethod", ctypes.c_void_p),
        ("CallStaticVoidMethodV", ctypes.c_void_p),
        ("CallStaticVoidMethodA", ctypes.c_void_p),
        ("GetStaticFieldID", ctypes.c_void_p),
        ("GetStaticObjectField", ctypes.c_void_p),
        ("GetStaticBooleanField", ctypes.c_void_p),
        ("GetStaticByteField", ctypes.c_void_p),
        ("GetStaticCharField", ctypes.c_void_p),
        ("GetStaticShortField", ctypes.c_void_p),
        ("GetStaticIntField", ctypes.c_void_p),
        ("GetStaticLongField", ctypes.c_void_p),
        ("GetStaticFloatField", ctypes.c_void_p),
        ("GetStaticDoubleField", ctypes.c_void_p),
        ("SetStaticObjectField", ctypes.c_void_p),
        ("SetStaticBooleanField", ctypes.c_void_p),
        ("SetStaticByteField", ctypes.c_void_p),
        ("SetStaticCharField", ctypes.c_void_p),
        ("SetStaticShortField", ctypes.c_void_p),
        ("SetStaticIntField", ctypes.c_void_p),
        ("SetStaticLongField", ctypes.c_void_p),
        ("SetStaticFloatField", ctypes.c_void_p),
        ("SetStaticDoubleField", ctypes.c_void_p),
        ("NewString", ctypes.c_void_p),
        ("GetStringLength", ctypes.c_void_p),
        ("GetStringChars", ctypes.c_void_p),
        ("ReleaseStringChars", ctypes.c_void_p),
        ("NewStringUTF", JNI_FUNCTYPE(ctypes.c_void_p, JNIEnv_p, ctypes.c_char_p)),
        ("GetStringUTFLength", ctypes.c_void_p),
        ("GetStringUTFChars", JNI_FUNCTYPE(ctypes.c_char_p, JNIEnv_p, ctypes.c_void_p, ctypes.c_void_p)),
        ("ReleaseStringUTFChars", JNI_FUNCTYPE(None, JNIEnv_p, ctypes.c_void_p, ctypes.c_char_p)),
        ("GetArrayLength", ctypes.c_void_p),
        ("NewObjectArray", ctypes.c_void_p),
        ("GetObjectArrayElement", ctypes.c_void_p),
        ("SetObjectArrayElement", ctypes.c_void_p),
        ("NewBooleanArray", ctypes.c_void_p),
        ("NewByteArray", ctypes.c_void_p),
        ("NewCharArray", ctypes.c_void_p),
        ("NewShortArray", ctypes.c_void_p),
        ("NewIntArray", ctypes.c_void_p),
        ("NewLongArray", ctypes.c_void_p),
        ("NewFloatArray", ctypes.c_void_p),
        ("NewDoubleArray", ctypes.c_void_p),
        ("GetBooleanArrayElements", ctypes.c_void_p),
        ("GetByteArrayElements", ctypes.c_void_p),
        ("GetCharArrayElements", ctypes.c_void_p),
        ("GetShortArrayElements", ctypes.c_void_p),
        ("GetIntArrayElements", ctypes.c_void_p),
        ("GetLongArrayElements", ctypes.c_void_p),
        ("GetFloatArrayElements", ctypes.c_void_p),
        ("GetDoubleArrayElements", ctypes.c_void_p),
        ("ReleaseBooleanArrayElements", ctypes.c_void_p),
        ("ReleaseByteArrayElements", ctypes.c_void_p),
        ("ReleaseCharArrayElements", ctypes.c_void_p),
        ("ReleaseShortArrayElements", ctypes.c_void_p),
        ("ReleaseIntArrayElements", ctypes.c_void_p),
        ("ReleaseLongArrayElements", ctypes.c_void_p),
        ("ReleaseFloatArrayElements", ctypes.c_void_p),
        ("ReleaseDoubleArrayElements", ctypes.c_void_p),
        ("GetBooleanArrayRegion", ctypes.c_void_p),
        ("GetByteArrayRegion", ctypes.c_void_p),
        ("GetCharArrayRegion", ctypes.c_void_p),
        ("GetShortArrayRegion", ctypes.c_void_p),
        ("GetIntArrayRegion", ctypes.c_void_p),
        ("GetLongArrayRegion", ctypes.c_void_p),
        ("GetFloatArrayRegion", ctypes.c_void_p),
        ("GetDoubleArrayRegion", ctypes.c_void_p),
        ("SetBooleanArrayRegion", ctypes.c_void_p),
        ("SetByteArrayRegion", ctypes.c_void_p),
        ("SetCharArrayRegion", ctypes.c_void_p),
        ("SetShortArrayRegion", ctypes.c_void_p),
        ("SetIntArrayRegion", ctypes.c_void_p),
        ("SetLongArrayRegion", ctypes.c_void_p),
        ("SetFloatArrayRegion", ctypes.c_void_p),
        ("SetDoubleArrayRegion", ctypes.c_void_p),
        ("RegisterNatives", ctypes.c_void_p),
        ("UnregisterNatives", ctypes.c_void_p),
        ("MonitorEnter", ctypes.c_void_p),
        ("MonitorExit", ctypes.c_void_p),
        ("GetJavaVM", ctypes.c_void_p),
        ("GetStringRegion", ctypes.c_void_p),
        ("GetStringUTFRegion", ctypes.c_void_p),
        ("GetPrimitiveArrayCritical", ctypes.c_void_p),
        ("ReleasePrimitiveArrayCritical", ctypes.c_void_p),
        ("GetStringCritical", ctypes.c_void_p),
        ("ReleaseStringCritical", ctypes.c_void_p),
        ("NewWeakGlobalRef", ctypes.c_void_p),
        ("DeleteWeakGlobalRef", ctypes.c_void_p),
        ("ExceptionCheck", ctypes.c_void_p),
        ("NewDirectByteBuffer", ctypes.c_void_p),
        ("GetDirectBufferAddress", ctypes.c_void_p),
        ("GetDirectBufferCapacity", ctypes.c_void_p),
        ("GetObjectRefType", ctypes.c_void_p)
    ]

# In JNI, the JNIEnv type is a pointer to a pointer to the function table.
JNIEnv._fields_ = [("functions", ctypes.POINTER(JNINativeInterface))]


# --- JVM Initialization ---
def initialize_jvm():
    """Creates and initializes the Java Virtual Machine."""
    options = (JavaVMOption * 1)()
    options[0].optionString = b"-Djava.class.path=."

    args = JavaVMInitArgs()
    args.version = 0x00010008  # JNI_VERSION_1_8
    args.nOptions = 1
    args.options = options
    args.ignoreUnrecognized = True

    jvm_pointer = JavaVM_p()
    env_pointer = JNIEnv_p()

    create_jvm_func = jvm.JNI_CreateJavaVM
    create_jvm_func.argtypes = [ctypes.POINTER(JavaVM_p), ctypes.POINTER(JNIEnv_p), ctypes.POINTER(JavaVMInitArgs)]
    create_jvm_func.restype = ctypes.c_int

    res = create_jvm_func(ctypes.byref(jvm_pointer), ctypes.byref(env_pointer), ctypes.byref(args))
    if res != 0:
        raise RuntimeError(f"Failed to create JVM: error code {res}")

    print("✅ JVM created successfully!")
    return jvm_pointer, env_pointer

# --- JNI Helper Function ---
def check_exception(env, env_p):
    """Checks if a JNI call caused a Java exception."""
    if env.ExceptionOccurred(env_p):
        env.ExceptionDescribe(env_p)
        env.ExceptionClear(env_p)
        raise RuntimeError("A Java exception occurred, check console for details.")

# --- Main Execution ---
if __name__ == "__main__":
    jvm_p, env_p = initialize_jvm()
    env = env_p.contents.functions.contents

    print("\n🚀 Calling Java method: System.getProperty('java.version')")

    java_string_arg = None
    java_version_obj = None
    try:
        # 1. Find the class
        system_class_str = b"java/lang/System"
        system_class = env.FindClass(env_p, system_class_str)
        if not system_class: raise RuntimeError(f"Failed to find class: {system_class_str.decode()}")
        check_exception(env, env_p)
        print(f"  - Found class: {system_class_str.decode()}")

        # 2. Get the static method ID
        method_name = b"getProperty"
        method_sig = b"(Ljava/lang/String;)Ljava/lang/String;"
        get_property_mid = env.GetStaticMethodID(env_p, system_class, method_name, method_sig)
        if not get_property_mid: raise RuntimeError(f"Failed to find method: {method_name.decode()}")
        check_exception(env, env_p)
        print(f"  - Found method: {method_name.decode()} with signature {method_sig.decode()}")

        # 3. Create the Java string argument
        prop_name_str = b"java.version"
        java_string_arg = env.NewStringUTF(env_p, prop_name_str)
        if not java_string_arg: raise RuntimeError("Failed to create Java string.")
        check_exception(env, env_p)
        print(f"  - Created Java string argument: '{prop_name_str.decode()}'")

        # 4. Call the static method using the 'A' (argument array) version
        args_array = (jvalue * 1)()
        args_array[0].l = java_string_arg

        java_version_obj = env.CallStaticObjectMethodA(env_p, system_class, get_property_mid, args_array)
        if not java_version_obj: raise RuntimeError("Java method call returned null.")
        check_exception(env, env_p)
        print("  - Successfully called the static method.")

        # 5. Convert the returned Java string to a Python string
        # The last argument to GetStringUTFChars can be NULL if we don't need to know if a copy was made.
        c_version_str = env.GetStringUTFChars(env_p, java_version_obj, None)
        check_exception(env, env_p)
        python_version_str = ctypes.string_at(c_version_str).decode('utf-8')

        # 6. Clean up the native string reference
        env.ReleaseStringUTFChars(env_p, java_version_obj, c_version_str)
        print("  - Converted result to Python string.")

        print("\n✅ Result from Java: " + python_version_str)

    except RuntimeError as e:
        print(f"\n❌ An error occurred: {e}")

    finally:
        # Crucially, we must clean up any local references we created to prevent
        # memory leaks.
        if java_string_arg:
            env.DeleteLocalRef(env_p, java_string_arg)
            print("  - Cleaned up local reference for argument string.")
        if java_version_obj:
            env.DeleteLocalRef(env_p, java_version_obj)
            print("  - Cleaned up local reference for result string.")

        # Destroying the JVM is complex and can cause hangs if other non-daemon threads are running.
        # It's often omitted in simple scripts for robustness. If you need to restart the JVM
        # in the same process, you would need to manage this carefully.
        # jvm_p.contents.contents.DestroyJavaVM(jvm_p)
        print("\nScript finished.")