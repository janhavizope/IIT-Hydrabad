/**
 * Frida Instrumentation Agent
 * Captures core Android behaviors: SharedPreferences, SQLite, File IO, ContentProviders, Network, Activities.
 */

Java.perform(function () {
    console.log("[Frida] Agent injected successfully");

    var Log = Java.use("android.util.Log");
    var TAG = "Frida-Instr";

    function logEvent(eventType, message) {
        // Output to Logcat for standard pipeline ingestion
        Log.i(TAG, "[" + eventType + "] " + message);
        // Output to Frida console for direct instrumentation ingestion
        send({ type: eventType, message: message });
    }

    // 1. SharedPreferences
    try {
        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        EditorImpl.putString.implementation = function (key, value) {
            logEvent("sharedpreferences", "Write String -> Key: " + key + ", Value: " + value);
            return this.putString(key, value);
        };
        EditorImpl.putInt.implementation = function (key, value) {
            logEvent("sharedpreferences", "Write Int -> Key: " + key + ", Value: " + value);
            return this.putInt(key, value);
        };
        EditorImpl.putBoolean.implementation = function (key, value) {
            logEvent("sharedpreferences", "Write Boolean -> Key: " + key + ", Value: " + value);
            return this.putBoolean(key, value);
        };
        console.log("[Frida] Hook registered: SharedPreferences");
    } catch (e) {
        console.error("Failed to hook SharedPreferences: " + e);
    }

    // 2. SQLite Database
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
            logEvent("database", "SQLite Query: " + sql);
            return this.rawQuery(sql, selectionArgs);
        };
        SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function (table, nullColumnHack, values) {
            logEvent("database", "SQLite Insert -> Table: " + table + ", Values: " + values);
            return this.insert(table, nullColumnHack, values);
        };
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            logEvent("database", "SQLite execSQL: " + sql);
            return this.execSQL(sql);
        };
        console.log("[Frida] Hook registered: SQLiteDatabase (rawQuery, insert, execSQL)");
    } catch (e) {
        console.error("Failed to hook SQLite: " + e);
    }

    // 3. File Read/Write Operations
    try {
        var File = Java.use("java.io.File");
        File.$init.overload('java.lang.String').implementation = function (pathname) {
            if (pathname && (pathname.indexOf("/sdcard") !== -1 || pathname.indexOf("/data/data") !== -1)) {
                logEvent("file_access", "File Open: " + pathname);
            }
            return this.$init(pathname);
        };

        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
            logEvent("file_access", "File Write: " + file.getAbsolutePath());
            return this.$init(file, append);
        };
        console.log("[Frida] Hook registered: File IO");
    } catch (e) {
        console.error("Failed to hook File I/O: " + e);
    }

    // 4. Content Provider Access (Contacts, SMS)
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            var uriString = uri.toString();
            if (uriString.indexOf("content://sms") !== -1 || 
                uriString.indexOf("content://contacts") !== -1 ||
                uriString.indexOf("content://call_log") !== -1) {
                logEvent("content_provider", "Sensitive Provider Query: " + uriString);
            } else {
                logEvent("content_provider", "Provider Query: " + uriString);
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        console.log("[Frida] Hook registered: ContentResolver.query");
    } catch (e) {
        console.error("Failed to hook ContentResolver: " + e);
    }

    // 5. Network Connections (HTTP/HTTPS)
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function (url) {
            logEvent("network", "URL Init: " + url);
            return this.$init(url);
        };
        console.log("[Frida] Hook registered: java.net.URL");
    } catch (e) {
        console.error("Failed to hook java.net.URL: " + e);
    }

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request) {
            logEvent("network", "OkHttp Request: " + request.url().toString());
            return this.newCall(request);
        };
        console.log("[Frida] Hook registered: OkHttpClient.newCall");
    } catch (e) {
        // OkHttp might not be present, ignore
    }

    // 6. Activity Transitions
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function () {
            var name = this.getClass().getName();
            logEvent("activity", "Activity onResume: " + name);
            this.onResume();
        };
        console.log("[Frida] Hook registered: Activity");
    } catch (e) {
        console.error("Failed to hook Activity: " + e);
    }

    console.log("[Frida] All hooks deployed");
});
