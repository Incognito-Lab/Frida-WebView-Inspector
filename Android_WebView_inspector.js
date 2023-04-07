//frida -U "<ProcessName>" -l Android_WebView_inspector.js
let Webview = Java.use("android.webkit.WebView");

// inspect settings of android.webkit.WebView class
Java.choose("android.webkit.WebView", {
    // check if there are any running webview instances
    onMatch: function(instance) {
        // webview must be running on the main thread, so scheduleOnMainThread() will force the function to run on the main thread
        Java.scheduleOnMainThread(function(){
            console.log('[+] Found an instance(s): ', instance);
            console.log('\n[+] Javascript Enable =>',instance.getSettings().getJavaScriptEnabled());
            console.log('\n[+] AllowUniversalAccessFromFileURLs Enable =>',instance.getSettings().getAllowUniversalAccessFromFileURLs());
            console.log('\n[+] AllowFileAccessFromFileURLs Enable =>',instance.getSettings().getAllowFileAccessFromFileURLs());
            console.log('\n[+] AllowFileAccess Enable =>',instance.getSettings().getAllowFileAccess());
        });
    },
    onComplete: function() {
        console.log("Finished enumerating instances!");
    }
});

// inspect Javascript Bridge
Webview.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function(obj, name) {
    console.log('\n[+] Bridge Call=>',name);
	this.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').call(this,obj, name);
}