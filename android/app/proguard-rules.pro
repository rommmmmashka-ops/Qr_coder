# Правила R8 / ProGuard для безпечного зменшення розміру додатку
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Збереження класів Google ML Kit / Barcode Scanning (для mobile_scanner)
-keep class com.google.mlkit.** { *; }
-keep class com.google.android.libraries.barhopper.** { *; }
-keep class com.google.photos.vision.barhopper.** { *; }
-dontwarn com.google.mlkit.**
-dontwarn com.google.android.gms.**
