package toolkit.coderstory;


import android.content.pm.Signature;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class CorePatchForR extends XposedHelper implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    /** 降级安装 */
    private static final String DOWNGRADE = "downgrade";
    /** 文件篡改 */
    private static final String AUTHCREAK = "authcreak";
    /** 签名不一致 */
    private static final String DIGESTCREAK = "digestCreak";
    /** 增强模式 */
    private static final String ENHANCEDMODE = "enhancedMode";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws IllegalAccessException, InvocationTargetException, InstantiationException {

        // 允许降级
        findAndHookMethod("com.android.server.pm.PackageManagerService", loadPackageParam.classLoader,
                "checkDowngrade",
                "com.android.server.pm.parsing.pkg.AndroidPackage",
                "android.content.pm.PackageInfoLite",
                XposedHelper.returnValChanger(DOWNGRADE, null)); // XC_MethodReplacement.returnConstant(null));
        // exists on flyme 9(Android 11) only
        findAndHookMethod("com.android.server.pm.PackageManagerService", loadPackageParam.classLoader,
                "checkDowngrade",
                "android.content.pm.PackageInfoLite",
                "android.content.pm.PackageInfoLite",
                XposedHelper.returnValChanger(DOWNGRADE, 1)); // XC_MethodReplacement.returnConstant(1));



        // apk内文件修改后 digest校验会失败
        hookAllMethods("android.util.jar.StrictJarVerifier", loadPackageParam.classLoader, "verifyMessageDigest", XposedHelper.returnValChanger(AUTHCREAK, true)); // XC_MethodReplacement.returnConstant(true));
        hookAllMethods("android.util.jar.StrictJarVerifier", loadPackageParam.classLoader, "verify", XposedHelper.returnValChanger(AUTHCREAK, true)); // XC_MethodReplacement.returnConstant(true));
        hookAllMethods("java.security.MessageDigest", loadPackageParam.classLoader, "isEqual", XposedHelper.returnValChanger(AUTHCREAK, true)); // XC_MethodReplacement.returnConstant(true));

        // Targeting R+ (version " + Build.VERSION_CODES.R + " and above) requires"
        // + " the resources.arsc of installed APKs to be stored uncompressed"
        // + " and aligned on a 4-byte boundary
        // target >=30 的情况下 resources.arsc 必须是未压缩的且4K对齐
        hookAllMethods("android.content.res.AssetManager", loadPackageParam.classLoader, "containsAllocatedTable", XposedHelper.returnValChanger(AUTHCREAK, false)); // XC_MethodReplacement.returnConstant(false));

        // No signature found in package of version " + minSignatureSchemeVersion
        // + " or newer for package " + apkPath
        findAndHookMethod("android.util.apk.ApkSignatureVerifier", loadPackageParam.classLoader, "getMinimumSignatureSchemeVersionForTargetSdk", int.class, XposedHelper.returnValChanger(AUTHCREAK, 0)); // XC_MethodReplacement.returnConstant(0));
        findAndHookMethod("com.android.apksig.ApkVerifier", loadPackageParam.classLoader, "getMinimumSignatureSchemeVersionForTargetSdk", int.class, XposedHelper.returnValChanger(AUTHCREAK, 0)); // XC_MethodReplacement.returnConstant(0));

        // Package " + packageName + " signatures do not match previously installed version; ignoring!"
        // public boolean checkCapability(String sha256String, @CertCapabilities int flags) {
        // public boolean checkCapability(SigningDetails oldDetails, @CertCapabilities int flags)
        hookAllMethods("android.content.pm.PackageParser", loadPackageParam.classLoader, "checkCapability", XposedHelper.returnValChanger(AUTHCREAK, true)); // XC_MethodReplacement.returnConstant(true));

        // 当verifyV1Signature抛出转换异常时，替换一个签名作为返回值
        Class<?> signingDetails = XposedHelpers.findClass("android.content.pm.PackageParser.SigningDetails", loadPackageParam.classLoader);
        Constructor<?> findConstructorExact = XposedHelpers.findConstructorExact(signingDetails, Signature[].class, Integer.TYPE);
        findConstructorExact.setAccessible(true);
        Class<?> packageParserException = XposedHelpers.findClass("android.content.pm.PackageParser.PackageParserException", loadPackageParam.classLoader);
        Field error = XposedHelpers.findField(packageParserException, "error");
        error.setAccessible(true);
        Object[] signingDetailsArgs = new Object[2];
        signingDetailsArgs[0] = new Signature[]{new Signature(SIGNATURE)};
        signingDetailsArgs[1] = 1;
        final Object newInstance = findConstructorExact.newInstance(signingDetailsArgs);
        hookAllMethods("android.util.apk.ApkSignatureVerifier", loadPackageParam.classLoader, "verifyV1Signature", new XC_MethodHook() {
            public void afterHookedMethod(MethodHookParam methodHookParam) throws Throwable {
                super.afterHookedMethod(methodHookParam);
                if (XposedHelper.getConfVal(DIGESTCREAK)) {
                    Throwable throwable = methodHookParam.getThrowable();
                    if (throwable != null) {
                        Throwable cause = throwable.getCause();
                        if (throwable.getClass() == packageParserException) {
                            if (error.getInt(throwable) == -103) {
                                methodHookParam.setResult(newInstance);
                            }
                        }
                        if (cause != null && cause.getClass() == packageParserException) {
                            if (error.getInt(cause) == -103) {
                                methodHookParam.setResult(newInstance);
                            }
                        }
                    }
                }
            }
        });




        //New package has a different signature
        //处理覆盖安装但签名不一致
        // Class<?> signingDetails = XposedHelpers.findClass("android.content.pm.PackageParser.SigningDetails", loadPackageParam.classLoader);
        hookAllMethods(signingDetails, "checkCapability", XposedHelper.returnValChanger(DIGESTCREAK, true)); // XC_MethodReplacement.returnConstant(true));

    }

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        hookAllMethods("android.content.pm.PackageParser", null, "getApkSigningVersion", XposedHelper.returnValChanger(ENHANCEDMODE, false, 1)); // XC_MethodReplacement.returnConstant(1));
        hookAllConstructors("android.util.jar.StrictJarVerifier", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                if (XposedHelper.getConfVal(ENHANCEDMODE, false)) param.args[3] = Boolean.FALSE;
            }
        });
    }
}
