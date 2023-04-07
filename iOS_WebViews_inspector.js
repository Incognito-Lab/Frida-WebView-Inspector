//frida -U <ProcessName> -l iOS_WebViews_inspector.js
//This Frida script checks if the Webview class is available in the current process. If it is available, it proceeds to use Frida's `choose` method to enumerate all instances of the class, and for each instance it calls the `onMatch` function.
//After Webview classes instance is initialized, in Frida CLI, `%reload` should be used to reload this script.

if (ObjC.available) {

  //Check iOS Version
  function iOSVersionFunc() {
    var processInfo = ObjC.classes.NSProcessInfo.processInfo();
    var versionString = processInfo.operatingSystemVersionString().toString(); //E.g. Version 14.0 (Build XXXXX)
    var versionTemp = versionString.split(' ');
    var version = versionTemp[1]; //E.g. 14.0
    return version
  }

  function inspect_UIWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.request().URL().toString());
  }

  function inspect_SFSafariViewController(SFSafariViewController) {
    //Do something;
  }

  function inspect_WKWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.URL().toString());
    if (8.0 < iOSVersionFloat && iOSVersionFloat <= 14.0) {
      //WKWebView javaScriptEnabled deprecated after iOS 14.0
      console.log('javaScriptEnabled: ', WebViewInstance.configuration().preferences().javaScriptEnabled());
    } else if (iOSVersionFloat >= 14.1) {
      //WKWebView allowsContentJavaScript
      console.log('allowsContentJavaScript: ', WebViewInstance.configuration().defaultWebpagePreferences().allowsContentJavaScript());
    }
    console.log('allowFileAccessFromFileURLs: ', WebViewInstance.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
    console.log('hasOnlySecureContent: ', WebViewInstance.hasOnlySecureContent().toString());
    console.log('allowUniversalAccessFromFileURLs: ', WebViewInstance.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
  }

  var iOSVersionStr = iOSVersionFunc();
  var iOSVersionFloat = parseFloat(iOSVersionStr)

  var UIWebView = ObjC.classes.UIWebView;
  if (UIWebView) {
    console.log(`===== Found UIWebView =====`);
    ObjC.choose(UIWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_UIWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for UIWebView! =====\n');
      }
    });
  }

  var WKWebView = ObjC.classes.WKWebView;
  if (WKWebView) {
    console.log(`===== Found WKWebView =====`);
    ObjC.choose(WKWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_WKWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for WKWebView! =====\n');
      }
    });
  }

  var SFSafariViewController = ObjC.classes.SFSafariViewController;
  if (SFSafariViewController) {
    console.log(`===== Found SFSafariViewController =====`);
    ObjC.choose(SFSafariViewController, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        //inspect_SFSafariViewController(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for SFSafariViewController! =====\n');
      }
    });
  }

  //Check if application use JavaScript Bridge (**Not tested yet**)
  //WKUserContentController
  var WKUserContentController = ObjC.classes.WKUserContentController;
  if (WKUserContentController) {
    Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WKUserContentController) =====");
        console.log(`\nClasss: \'WKUserContentController\' Method: \'- addScriptMessageHandler:name:\' Called`);
        var handler = new ObjC.Object(args[2]);
        var name = new ObjC.Object(args[3]);
        console.log(name, '->', handler.$className);
      }
    });
  }

  //WebViewJavascriptBridge
  var WebViewJavascriptBridge = ObjC.classes.WebViewJavascriptBridge;
  if (WebViewJavascriptBridge) {
    Interceptor.attach(WebViewJavascriptBridge['- registerHandler:handler:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WebViewJavascriptBridge) =====");
        console.log(`\nClasss: \'WebViewJavascriptBridge\' Method: \'- registerHandler:handler:\' Called`);
        var name = new ObjC.Object(args[2].toString());
        console.log(name, '->', handler.$className);
        //var handler = new ObjC.Object();
      }
    });
  }

  /*
    //Used to inspectloadHTMLString on WKWebView
    var WebViewClassName = "WKWebView"
    var methodName = "- loadHTMLString:baseURL:";
    var methodAddr = ObjC.classes[WebViewClassName][methodName].implementation;
    Interceptor.attach(methodAddr, {
      onEnter: function (args) {
        console.log(`\n======================================================================`);
        console.log(`Classs: \'${WebViewClassName}\' Method: \'${methodName}\' Called`);
        console.log(`HTML string: ${new ObjC.Object(ptr(args[2])).toString()}`);
        console.log(`Base URL: ${args[3].toString()}`);
      },
      onLeave: function (returnVal) {
        console.log(`Return Value: ${returnVal}`);
      }
    });
    */

}