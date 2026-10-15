Optional branding (NOT wired in yet). To use it:
 1. Copy everything inside branding/res/ into app/src/main/res/  (merge folders).
 2. In AndroidManifest.xml, on <application> set:
      android:icon="@mipmap/ic_launcher"
      android:roundIcon="@mipmap/ic_launcher_round"
      android:label="@string/app_name"
 3. In MainActivity.java replace the two "Bug Hunter" title strings (home bar + drawer header) with getString(R.string.app_name).
