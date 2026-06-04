Java.perform(function () {
    console.log("[+] Frida injected successfully");

    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function (bundle) {
        console.log("[+] Activity started: " + this.getClass().getName());
        return this.onCreate(bundle);
    };
});