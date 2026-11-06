import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:ui' as ui;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:gal/gal.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';

void main() {
  runApp(const MyApp());
}

/// Допоміжний клас для парольного шифрування та розшифрування даних QR-коду
/// (потоковий шифр ChaCha20 + автентифікаційний MAC-тег для перевірки пароля).
class QrCryptoHelper {
  static const String prefix = 'QRCENC1:';
  static const int _saltLength = 8;
  static const int _tagLength = 8;

  static bool isEncrypted(String data) =>
      data.trim().toUpperCase().startsWith(prefix);

  static int _rotl32(int val, int shift) =>
      ((val << shift) & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) >>> (32 - shift));

  static void _quarterRound(List<int> s, int a, int b, int c, int d) {
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF;
    s[d] = _rotl32(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF;
    s[b] = _rotl32(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF;
    s[d] = _rotl32(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF;
    s[b] = _rotl32(s[b] ^ s[c], 7);
  }

  static void _chachaPermute(List<int> state) {
    for (int i = 0; i < 10; i++) {
      _quarterRound(state, 0, 4, 8, 12);
      _quarterRound(state, 1, 5, 9, 13);
      _quarterRound(state, 2, 6, 10, 14);
      _quarterRound(state, 3, 7, 11, 15);
      _quarterRound(state, 0, 5, 10, 15);
      _quarterRound(state, 1, 6, 11, 12);
      _quarterRound(state, 2, 7, 8, 13);
      _quarterRound(state, 3, 4, 9, 14);
    }
  }

  static List<int> _deriveKeyState(Uint8List passwordBytes, Uint8List salt) {
    final state = List<int>.filled(16, 0);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < salt.length; i++) {
      state[4 + (i >> 2)] ^= salt[i] << ((i & 3) * 8);
    }

    for (int round = 0; round < 1000; round++) {
      for (int i = 0; i < passwordBytes.length; i++) {
        final idx = 6 + ((i + round) % 10);
        state[idx] =
            (state[idx] ^ (passwordBytes[i] << ((i & 3) * 8))) & 0xFFFFFFFF;
      }
      state[15] = (state[15] + round + passwordBytes.length) & 0xFFFFFFFF;
      _chachaPermute(state);
    }
    return state;
  }

  static Uint8List _processKeystream(Uint8List input, List<int> keyState) {
    final output = Uint8List(input.length);
    final block = List<int>.filled(16, 0);
    final keystreamBlock = Uint8List(64);

    final totalBlocks = (input.length + 63) ~/ 64;
    for (int b = 0; b < totalBlocks; b++) {
      for (int i = 0; i < 16; i++) {
        block[i] = keyState[i];
      }
      block[12] = (block[12] ^ b ^ 0xA5A5A5A5) & 0xFFFFFFFF;
      _chachaPermute(block);

      for (int i = 0; i < 16; i++) {
        final word = (block[i] + keyState[i]) & 0xFFFFFFFF;
        keystreamBlock[i * 4] = word & 0xFF;
        keystreamBlock[i * 4 + 1] = (word >>> 8) & 0xFF;
        keystreamBlock[i * 4 + 2] = (word >>> 16) & 0xFF;
        keystreamBlock[i * 4 + 3] = (word >>> 24) & 0xFF;
      }

      final offset = b * 64;
      final chunkLen = min(64, input.length - offset);
      for (int i = 0; i < chunkLen; i++) {
        output[offset + i] = input[offset + i] ^ keystreamBlock[i];
      }
    }
    return output;
  }

  static Uint8List _computeMacTag(
    Uint8List salt,
    Uint8List ciphertext,
    List<int> keyState,
  ) {
    final macState = List<int>.generate(
      16,
      (i) => (keyState[i] ^ 0x5A5A5A5A) & 0xFFFFFFFF,
    );

    void absorb(Uint8List bytes) {
      for (int i = 0; i < bytes.length; i++) {
        final wordIdx = (i % 12) + 4;
        macState[wordIdx] =
            (macState[wordIdx] ^ (bytes[i] << ((i & 3) * 8))) & 0xFFFFFFFF;
        if ((i & 15) == 15 || i == bytes.length - 1) {
          macState[0] = (macState[0] + i + 1) & 0xFFFFFFFF;
          _chachaPermute(macState);
        }
      }
    }

    absorb(salt);
    absorb(ciphertext);
    _chachaPermute(macState);

    final tag = Uint8List(_tagLength);
    for (int i = 0; i < _tagLength; i++) {
      tag[i] = (macState[i >> 2] >>> ((i & 3) * 8)) & 0xFF;
    }
    return tag;
  }

  /// Шифрує рядок [plainText] за допомогою пароля [password].
  static String encrypt(String plainText, String password) {
    final rng = Random.secure();
    final salt = Uint8List.fromList(
      List<int>.generate(_saltLength, (_) => rng.nextInt(256)),
    );
    final passwordBytes = Uint8List.fromList(utf8.encode(password));
    final plainBytes = Uint8List.fromList(utf8.encode(plainText));

    final keyState = _deriveKeyState(passwordBytes, salt);
    final cipherBytes = _processKeystream(plainBytes, keyState);
    final tag = _computeMacTag(salt, cipherBytes, keyState);

    final combined = Uint8List(_saltLength + _tagLength + cipherBytes.length);
    combined.setRange(0, _saltLength, salt);
    combined.setRange(_saltLength, _saltLength + _tagLength, tag);
    combined.setRange(_saltLength + _tagLength, combined.length, cipherBytes);

    final encoded = base64UrlEncode(combined).replaceAll('=', '');
    return '$prefix$encoded';
  }

  /// Розшифровує рядок [encryptedPayload] паролем [password].
  /// Повертає розшифрований текст або `null`, якщо пароль невірний чи дані пошкоджені.
  static String? decrypt(String encryptedPayload, String password) {
    final trimmed = encryptedPayload.trim();
    if (!isEncrypted(trimmed)) return null;

    var b64 = trimmed.substring(prefix.length).trim();
    final mod = b64.length % 4;
    if (mod == 1) return null;
    if (mod > 0) {
      b64 = b64.padRight(b64.length + (4 - mod), '=');
    }

    try {
      final combined = base64Url.decode(b64);
      if (combined.length <= _saltLength + _tagLength) return null;

      final salt = Uint8List.sublistView(combined, 0, _saltLength);
      final actualTag = Uint8List.sublistView(
        combined,
        _saltLength,
        _saltLength + _tagLength,
      );
      final cipherBytes = Uint8List.sublistView(
        combined,
        _saltLength + _tagLength,
      );

      final passwordBytes = Uint8List.fromList(utf8.encode(password));
      final keyState = _deriveKeyState(passwordBytes, salt);
      final expectedTag = _computeMacTag(salt, cipherBytes, keyState);

      int diff = 0;
      for (int i = 0; i < _tagLength; i++) {
        diff |= actualTag[i] ^ expectedTag[i];
      }
      if (diff != 0) return null;

      final plainBytes = _processKeystream(cipherBytes, keyState);
      return utf8.decode(plainBytes);
    } catch (_) {
      return null;
    }
  }
}

/// Утиліта для контролю тимчасових файлів, кешу плагінів та оперативної пам’яті.
class AppStorageCleaner {
  /// Обмежує розмір RAM-кешу декодованих зображень Flutter (замість стандартних 100 МБ -> 20 МБ).
  static void configureCompactMemoryCache() {
    try {
      final imageCache = PaintingBinding.instance.imageCache;
      imageCache.maximumSize = 40;
      imageCache.maximumSizeBytes = 20 * 1024 * 1024;
    } catch (_) {}
  }

  /// Підраховує обсяг тимчасових файлів у системній кеш-директорії додатку.
  static Future<({int fileCount, int totalBytes})> inspectTempStorage() async {
    if (kIsWeb) return (fileCount: 0, totalBytes: 0);
    int count = 0;
    int bytes = 0;
    try {
      final tempDir = Directory.systemTemp;
      if (await tempDir.exists()) {
        await for (final entity in tempDir.list(
          recursive: true,
          followLinks: false,
        )) {
          if (entity is File) {
            try {
              final len = await entity.length();
              count++;
              bytes += len;
            } catch (_) {}
          }
        }
      }
    } catch (_) {}
    return (fileCount: count, totalBytes: bytes);
  }

  /// Видаляє тимчасові файли плагінів (file_picker, gal, тимчасові зображення)
  /// та очищує кеш зображень у пам’яті. Повертає кількість видалених байтів.
  static Future<int> clearTemporaryStorage() async {
    try {
      final imageCache = PaintingBinding.instance.imageCache;
      imageCache.clear();
      imageCache.clearLiveImages();
    } catch (_) {}

    if (kIsWeb) return 0;

    int freedBytes = 0;
    try {
      final tempDir = Directory.systemTemp;
      if (await tempDir.exists()) {
        await for (final entity in tempDir.list(
          recursive: true,
          followLinks: false,
        )) {
          if (entity is File) {
            try {
              final len = await entity.length();
              await entity.delete();
              freedBytes += len;
            } catch (_) {}
          }
        }
      }
    } catch (_) {}
    return freedBytes;
  }

  static String formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes Б';
    final kb = bytes / 1024;
    if (kb < 1024) return '${kb.toStringAsFixed(1)} КБ';
    final mb = kb / 1024;
    return '${mb.toStringAsFixed(2)} МБ';
  }
}

/// Рівень безпеки URL-адреси при перевірці.
enum UrlRiskLevel {
  safe('Безпечне з’єднання', Icons.verified_user_rounded, Color(0xFF059669)),
  warning('Потребує уваги', Icons.warning_amber_rounded, Color(0xFFD97706)),
  danger('Високий ризик', Icons.gpp_bad_rounded, Color(0xFFDC2626));

  final String label;
  final IconData icon;
  final Color color;
  const UrlRiskLevel(this.label, this.icon, this.color);
}

/// Результат евристичної перевірки безпеки посилання та очищеного вмісту сторінки.
class SafePageAnalysis {
  final String originalUrl;
  final String finalUrl;
  final List<String> redirectChain;
  final UrlRiskLevel riskLevel;
  final List<String> securityNotes;
  final int? statusCode;
  final String contentType;
  final String pageTitle;
  final String metaDescription;
  final List<String> textBlocks;
  final List<({String text, String url})> links;
  final String rawSource;
  final Map<String, String> responseHeaders;
  final String? certIssuer;
  final String? certSubject;
  final DateTime? certValidUntil;

  const SafePageAnalysis({
    required this.originalUrl,
    required this.finalUrl,
    required this.redirectChain,
    required this.riskLevel,
    required this.securityNotes,
    required this.statusCode,
    required this.contentType,
    required this.pageTitle,
    required this.metaDescription,
    required this.textBlocks,
    required this.links,
    required this.rawSource,
    required this.responseHeaders,
    this.certIssuer,
    this.certSubject,
    this.certValidUntil,
  });
}

/// Аналізатор безпеки URL та парсер безпечного режиму читання (без виконання JS).
class SafeWebInspector {
  static const Set<String> _knownShorteners = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'ow.ly',
    'is.gd',
    'buff.ly',
    'cutt.ly',
    'rb.gy',
    'tiny.cc',
    'shorturl.at',
  };

  static const List<String> _dangerousExtensions = [
    '.apk',
    '.exe',
    '.msi',
    '.bat',
    '.cmd',
    '.scr',
    '.vbs',
    '.jar',
    '.dmg',
    '.sh',
  ];

  /// Перевіряє URI на підозрілі ознаки фішингу або небезпечної схеми.
  static ({UrlRiskLevel level, List<String> notes}) evaluateUriSecurity(
    Uri uri, {
    List<String> redirectChain = const [],
  }) {
    final notes = <String>[];
    var level = UrlRiskLevel.safe;

    void escalate(UrlRiskLevel newLevel) {
      if (newLevel.index > level.index) {
        level = newLevel;
      }
    }

    final scheme = uri.scheme.toLowerCase();
    final host = uri.host.toLowerCase();

    if (scheme != 'https') {
      notes.add(
        'З’єднання використовує незахищений протокол (${scheme.toUpperCase()} замість HTTPS). Дані передаються у відкритому вигляді.',
      );
      escalate(UrlRiskLevel.warning);
    } else {
      notes.add('Використовується захищений протокол шифрування HTTPS.');
    }

    if (uri.userInfo.isNotEmpty) {
      notes.add(
        'Адреса містить символ "@" перед доменом (${uri.userInfo}@...) — це типова ознака маскування фішингового посилання!',
      );
      escalate(UrlRiskLevel.danger);
    }

    final isIpAddress =
        RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host) || host.contains(':');
    if (isIpAddress) {
      notes.add(
        'Замість доменного імені використовується пряма IP-адреса ($host).',
      );
      escalate(UrlRiskLevel.danger);
    }

    if (host.contains('xn--')) {
      notes.add(
        'Домен містить Punycode ($host) — можлива підміна схожих кириличних та латинських літер (IDN-атака).',
      );
      escalate(UrlRiskLevel.warning);
    }

    if (_knownShorteners.contains(host)) {
      notes.add(
        'Посилання веде через сервіс скорочення адрес ($host), який приховує кінцевий сайт.',
      );
      escalate(UrlRiskLevel.warning);
    }

    if (uri.hasPort && uri.port != 80 && uri.port != 443) {
      notes.add('Використовується нестандартний мережевий порт: ${uri.port}.');
      escalate(UrlRiskLevel.warning);
    }

    final lowerPath = uri.path.toLowerCase();
    for (final ext in _dangerousExtensions) {
      if (lowerPath.endsWith(ext)) {
        notes.add(
          'Посилання веде безпосередньо на виконуваний або інсталяційний файл ($ext)!',
        );
        escalate(UrlRiskLevel.danger);
        break;
      }
    }

    if (redirectChain.length > 1) {
      notes.add(
        'Виявлено перенаправлення (${redirectChain.length - 1} редиректів) до кінцевої адреси: $host.',
      );
    }

    return (level: level, notes: notes);
  }

  /// Декодує базові HTML-сутності для чистого відображення тексту.
  static String decodeHtmlEntities(String input) {
    return input
        .replaceAll('&nbsp;', ' ')
        .replaceAll('&amp;', '&')
        .replaceAll('&lt;', '<')
        .replaceAll('&gt;', '>')
        .replaceAll('&quot;', '"')
        .replaceAll('&#39;', "'")
        .replaceAll('&apos;', "'")
        .replaceAll('&mdash;', '—')
        .replaceAll('&ndash;', '–')
        .replaceAll('&laquo;', '«')
        .replaceAll('&raquo;', '»')
        .replaceAll('&copy;', '©')
        .replaceAllMapped(RegExp(r'&#(\d+);'), (match) {
          final code = int.tryParse(match.group(1) ?? '');
          return code != null ? String.fromCharCode(code) : match.group(0)!;
        })
        .replaceAllMapped(RegExp(r'&#x([0-9a-fA-F]+);'), (match) {
          final code = int.tryParse(match.group(1) ?? '', radix: 16);
          return code != null ? String.fromCharCode(code) : match.group(0)!;
        });
  }

  static String _stripTags(String htmlFragment) {
    final withoutTags = htmlFragment.replaceAll(RegExp(r'<[^>]*>'), ' ');
    return decodeHtmlEntities(
      withoutTags,
    ).replaceAll(RegExp(r'\s+'), ' ').trim();
  }

  /// Витягує безпечний для читання вміст із сирого HTML-коду (без скриптів і стилів).
  static ({
    String title,
    String description,
    List<String> blocks,
    List<({String text, String url})> links,
  })
  parseHtmlForSafeReading(String html, Uri baseUri) {
    // 1. Видаляємо потенційно небезпечні та технічні блоки: script, style, svg, noscript, iframe
    final sanitized = html.replaceAll(
      RegExp(
        r'<(script|style|noscript|svg|iframe|object|embed|head\s*>)[\s\S]*?<\/\1>',
        caseSensitive: false,
      ),
      ' ',
    );

    // 2. Витягуємо <title>
    String title = '';
    final titleMatch = RegExp(
      r'<title[^>]*>([\s\S]*?)<\/title>',
      caseSensitive: false,
    ).firstMatch(html);
    if (titleMatch != null) {
      title = _stripTags(titleMatch.group(1) ?? '');
    }

    // 3. Витягуємо <meta name="description" content="...">
    String description = '';
    final metaMatches = RegExp(
      r'<meta\s+[^>]*>',
      caseSensitive: false,
    ).allMatches(html);
    for (final m in metaMatches) {
      final tag = m.group(0) ?? '';
      final isDesc = RegExp(
        r'''(name|property)\s*=\s*["'](description|og:description)["']''',
        caseSensitive: false,
      ).hasMatch(tag);
      if (isDesc) {
        final contentMatch = RegExp(
          r'''content\s*=\s*["']([^"']*)["']''',
          caseSensitive: false,
        ).firstMatch(tag);
        if (contentMatch != null) {
          description = decodeHtmlEntities(
            contentMatch.group(1) ?? '',
          ).trim();
          if (description.isNotEmpty) break;
        }
      }
    }

    // 4. Витягуємо заголовки (h1-h3), абзаци (p), елементи списку (li)
    final blocks = <String>[];
    final blockRegex = RegExp(
      r'<(h1|h2|h3|p|li|blockquote)[^>]*>([\s\S]*?)<\/\1>',
      caseSensitive: false,
    );
    for (final match in blockRegex.allMatches(sanitized)) {
      final tagName = (match.group(1) ?? '').toLowerCase();
      final text = _stripTags(match.group(2) ?? '');
      if (text.length < 2) continue;

      if (tagName.startsWith('h')) {
        blocks.add('## $text');
      } else if (tagName == 'li') {
        blocks.add('• $text');
      } else {
        blocks.add(text);
      }
      if (blocks.length >= 120) break;
    }

    // Якщо структурованих тегів не знайдено — беремо загальний очищений текст тіла сторінки
    if (blocks.isEmpty) {
      final bodyCleaned = html.replaceAll(
        RegExp(
          r'<(script|style|head|svg|noscript)[\s\S]*?<\/\1>',
          caseSensitive: false,
        ),
        ' ',
      );
      final plain = _stripTags(bodyCleaned);
      if (plain.isNotEmpty) {
        blocks.add(plain);
      }
    }

    // 5. Витягуємо посилання <a href="...">...</a>
    final links = <({String text, String url})>[];
    final seenUrls = <String>{};
    final linkRegex = RegExp(
      r'''<a\s+[^>]*href\s*=\s*["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>''',
      caseSensitive: false,
    );
    for (final match in linkRegex.allMatches(sanitized)) {
      final rawHref = decodeHtmlEntities(match.group(1) ?? '').trim();
      if (rawHref.isEmpty ||
          rawHref.toLowerCase().startsWith('javascript:') ||
          rawHref.toLowerCase().startsWith('vbscript:') ||
          rawHref.toLowerCase().startsWith('data:')) {
        continue;
      }
      final resolvedUri = baseUri.resolve(rawHref);
      if (resolvedUri.scheme != 'http' && resolvedUri.scheme != 'https') {
        continue;
      }
      final resolvedStr = resolvedUri.toString();
      if (seenUrls.add(resolvedStr)) {
        final anchorText = _stripTags(match.group(2) ?? '');
        links.add((
          text: anchorText.isNotEmpty ? anchorText : resolvedStr,
          url: resolvedStr,
        ));
        if (links.length >= 80) break;
      }
    }

    return (
      title: title,
      description: description,
      blocks: blocks,
      links: links,
    );
  }
}

enum QrDataType {
  text('Текст', Icons.notes_rounded, 'Звичайний текст або нотатка'),
  url('URL', Icons.language_rounded, 'Посилання на веб-сайт'),
  contact('Контакт', Icons.badge_outlined, 'Візитка (ім’я, телефон, email)'),
  wifi('Wi-Fi', Icons.wifi_rounded, 'Підключення до мережі Wi-Fi'),
  geo('Геолокація', Icons.location_on_outlined, 'Координати або місце на карті');

  final String label;
  final IconData icon;
  final String subtitle;
  const QrDataType(this.label, this.icon, this.subtitle);
}

enum WifiEncryption {
  wpa('WPA / WPA2', 'WPA'),
  wep('WEP', 'WEP'),
  none('Без пароля', 'nopass');

  final String label;
  final String qrValue;
  const WifiEncryption(this.label, this.qrValue);
}

enum CenterIconMode {
  none('Без іконки', null),
  auto('Авто (за типом)', null),
  lock('Замок', Icons.lock_rounded),
  wifi('Wi-Fi', Icons.wifi_rounded),
  link('Посилання', Icons.language_rounded),
  person('Контакт', Icons.person_rounded),
  location('Локація', Icons.location_on_rounded),
  star('Зірка', Icons.star_rounded);

  final String label;
  final IconData? icon;
  const CenterIconMode(this.label, this.icon);
}

class QrColorOption {
  final String label;
  final Color color;
  const QrColorOption(this.label, this.color);
}

const List<QrColorOption> kQrColorOptions = [
  QrColorOption('Чорний', Color(0xFF111827)),
  QrColorOption('Індиго', Color(0xFF312E81)),
  QrColorOption('Синій', Color(0xFF0C4A6E)),
  QrColorOption('Смарагдовий', Color(0xFF065F46)),
  QrColorOption('Бордовий', Color(0xFF881337)),
  QrColorOption('Фіолетовий', Color(0xFF581C87)),
];

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  ThemeMode _themeMode = ThemeMode.system;

  void _toggleTheme() {
    setState(() {
      _themeMode =
          _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    });
  }

  ThemeData _buildTheme(Brightness brightness) {
    final colorScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF4F46E5),
      brightness: brightness,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: colorScheme,
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: colorScheme.surfaceContainerLowest,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 14,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: colorScheme.outlineVariant),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: colorScheme.outlineVariant),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: colorScheme.primary, width: 2),
        ),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: BorderSide(color: colorScheme.outlineVariant.withAlpha(140)),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Генератор QR-кодів',
      debugShowCheckedModeBanner: false,
      themeMode: _themeMode,
      theme: _buildTheme(Brightness.light),
      darkTheme: _buildTheme(Brightness.dark),
      home: QrGeneratorPage(
        onToggleTheme: _toggleTheme,
        themeMode: _themeMode,
      ),
    );
  }
}

class QrGeneratorPage extends StatefulWidget {
  final VoidCallback? onToggleTheme;
  final ThemeMode themeMode;

  const QrGeneratorPage({
    super.key,
    this.onToggleTheme,
    this.themeMode = ThemeMode.system,
  });

  @override
  State<QrGeneratorPage> createState() => _QrGeneratorPageState();
}

class _QrGeneratorPageState extends State<QrGeneratorPage> {
  QrDataType _selectedType = QrDataType.text;

  // Контролери для полів введення
  final _textController = TextEditingController();
  final _urlController = TextEditingController();

  final _contactNameController = TextEditingController();
  final _contactPhoneController = TextEditingController();
  final _contactEmailController = TextEditingController();

  final _wifiSsidController = TextEditingController();
  final _wifiPasswordController = TextEditingController();
  WifiEncryption _wifiEncryption = WifiEncryption.wpa;
  bool _obscureWifiPassword = true;

  final _geoLatController = TextEditingController();
  final _geoLngController = TextEditingController();
  final _geoQueryController = TextEditingController();

  // Налаштування шифрування QR-коду паролем
  bool _encryptWithPassword = false;
  final _encryptionPasswordController = TextEditingController();
  bool _obscureEncryptionPassword = true;

  // Налаштування кастомізації QR-коду
  Color _qrColor = kQrColorOptions.first.color;
  QrDataModuleShape _dataModuleShape = QrDataModuleShape.square;
  QrEyeShape _eyeShape = QrEyeShape.square;
  CenterIconMode _centerIconMode = CenterIconMode.auto;

  // Дані згенерованого QR-коду
  String? _generatedQrData;
  QrDataType? _generatedQrType;
  bool _generatedQrEncrypted = false;
  bool _isSaving = false;

  bool get _isDesktop =>
      !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);

  bool get _isMobile => !kIsWeb && (Platform.isAndroid || Platform.isIOS);

  IconData? get _effectiveCenterIcon {
    switch (_centerIconMode) {
      case CenterIconMode.none:
        return null;
      case CenterIconMode.auto:
        if (_generatedQrEncrypted) {
          return Icons.lock_rounded;
        }
        return (_generatedQrType ?? _selectedType).icon;
      default:
        return _centerIconMode.icon;
    }
  }

  @override
  void initState() {
    super.initState();
    AppStorageCleaner.configureCompactMemoryCache();
    // Автоматично очищуємо залишкові тимчасові файли попередніх сесій при старті
    unawaited(AppStorageCleaner.clearTemporaryStorage());
  }

  @override
  void dispose() {
    _textController.dispose();
    _urlController.dispose();
    _contactNameController.dispose();
    _contactPhoneController.dispose();
    _contactEmailController.dispose();
    _wifiSsidController.dispose();
    _wifiPasswordController.dispose();
    _geoLatController.dispose();
    _geoLngController.dispose();
    _geoQueryController.dispose();
    _encryptionPasswordController.dispose();
    super.dispose();
  }

  String _escapeSpecialChars(String input) {
    return input
        .replaceAll(r'\', r'\\')
        .replaceAll(';', r'\;')
        .replaceAll(',', r'\,')
        .replaceAll(':', r'\:');
  }

  String _unescapeSpecialChars(String input) {
    return input.replaceAllMapped(
      RegExp(r'\\([\\;,:])'),
      (match) => match.group(1)!,
    );
  }

  String? _extractTagValue(String source, String tag) {
    final pattern = RegExp(
      '(?:^|(?<!\\\\);)\\s*${RegExp.escape(tag)}:((?:\\\\.|[^;])*)',
      caseSensitive: false,
    );
    final match = pattern.firstMatch(source);
    if (match == null) return null;
    return _unescapeSpecialChars(match.group(1) ?? '');
  }

  String? _extractVCardField(String vcard, String fieldPrefix) {
    final lines = vcard.split(RegExp(r'\r?\n'));
    for (final line in lines) {
      final upper = line.toUpperCase();
      if (upper.startsWith('$fieldPrefix:') ||
          upper.startsWith('$fieldPrefix;')) {
        final colonIndex = line.indexOf(':');
        if (colonIndex != -1 && colonIndex + 1 < line.length) {
          return line.substring(colonIndex + 1).trim();
        }
      }
    }
    return null;
  }

  /// Перевіряє, чи рядок є веб-посиланням, або містить URL.
  String? _extractHttpUrl(String text) {
    final trimmed = text.trim();
    final lower = trimmed.toLowerCase();
    if (lower.startsWith('http://') || lower.startsWith('https://')) {
      return trimmed;
    }
    final match = RegExp(
      r'https?:\/\/[^\s;,"<>]+',
      caseSensitive: false,
    ).firstMatch(trimmed);
    return match?.group(0);
  }

  /// Відкриває вбудований безпечний переглядач сторінок для [url].
  void _openSafeWebViewer(String url) {
    var normalized = url.trim();
    if (normalized.isEmpty) {
      _showSnackBar('Введіть адресу сайту (URL)');
      return;
    }
    final lower = normalized.toLowerCase();
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      normalized = 'https://$normalized';
    }

    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => SafeWebViewerPage(initialUrl: normalized),
      ),
    );
  }

  void _clearCurrentInputs() {
    setState(() {
      switch (_selectedType) {
        case QrDataType.text:
          _textController.clear();
          break;
        case QrDataType.url:
          _urlController.clear();
          break;
        case QrDataType.contact:
          _contactNameController.clear();
          _contactPhoneController.clear();
          _contactEmailController.clear();
          break;
        case QrDataType.wifi:
          _wifiSsidController.clear();
          _wifiPasswordController.clear();
          _wifiEncryption = WifiEncryption.wpa;
          break;
        case QrDataType.geo:
          _geoLatController.clear();
          _geoLngController.clear();
          _geoQueryController.clear();
          break;
      }
    });
  }

  /// Відкриває екран камери для сканування QR-коду (на мобільних пристроях).
  Future<void> _openScanner() async {
    final scannedData = await Navigator.of(context).push<String>(
      MaterialPageRoute(
        builder: (context) => const QrScannerPage(),
      ),
    );

    if (scannedData == null || scannedData.isEmpty || !mounted) return;

    _handleIncomingQrData(scannedData);
  }

  /// Обробляє вхідний рядок QR-коду: якщо він зашифрований — запитує пароль.
  void _handleIncomingQrData(String rawData) {
    if (QrCryptoHelper.isEncrypted(rawData)) {
      setState(() {
        _generatedQrData = rawData.trim();
        _generatedQrEncrypted = true;
      });
      _showDecryptDialog(initialEncryptedData: rawData.trim());
    } else {
      _applyScannedData(rawData);
      _showScannedResultDialog(rawData);
    }
  }

  /// Діалогове вікно введення пароля для розшифрування QR-коду.
  Future<void> _showDecryptDialog({String? initialEncryptedData}) async {
    final prefilled =
        initialEncryptedData ??
        (_generatedQrData != null &&
                QrCryptoHelper.isEncrypted(_generatedQrData!)
            ? _generatedQrData!
            : '');

    final decrypted = await showDialog<String>(
      context: context,
      builder: (dialogContext) => _DecryptQrDialog(
        initialEncryptedData: prefilled,
        lockEncryptedField: initialEncryptedData != null,
      ),
    );

    if (decrypted == null || !mounted) return;

    _applyScannedData(decrypted);
    _showScannedResultDialog(decrypted, wasDecrypted: true);
  }

  /// Розпізнає тип сканованого або розшифрованого QR-коду та заповнює відповідні поля форми.
  void _applyScannedData(String raw) {
    final lowerRaw = raw.toLowerCase();

    setState(() {
      _generatedQrData = raw;
      _generatedQrEncrypted = false;

      if (lowerRaw.startsWith('wifi:')) {
        _selectedType = QrDataType.wifi;
        _generatedQrType = QrDataType.wifi;
        final body = raw.substring(5);
        _wifiSsidController.text = _extractTagValue(body, 'S') ?? '';
        _wifiPasswordController.text = _extractTagValue(body, 'P') ?? '';
        final auth = (_extractTagValue(body, 'T') ?? 'WPA').toUpperCase();
        if (auth == 'WEP') {
          _wifiEncryption = WifiEncryption.wep;
        } else if (auth == 'NOPASS' || auth.isEmpty) {
          _wifiEncryption = WifiEncryption.none;
        } else {
          _wifiEncryption = WifiEncryption.wpa;
        }
      } else if (lowerRaw.startsWith('mecard:')) {
        _selectedType = QrDataType.contact;
        _generatedQrType = QrDataType.contact;
        final body = raw.substring(7);
        _contactNameController.text = _extractTagValue(body, 'N') ?? '';
        _contactPhoneController.text = _extractTagValue(body, 'TEL') ?? '';
        _contactEmailController.text = _extractTagValue(body, 'EMAIL') ?? '';
      } else if (lowerRaw.contains('begin:vcard')) {
        _selectedType = QrDataType.contact;
        _generatedQrType = QrDataType.contact;
        _contactNameController.text =
            _extractVCardField(raw, 'FN') ?? _extractVCardField(raw, 'N') ?? '';
        _contactPhoneController.text = _extractVCardField(raw, 'TEL') ?? '';
        _contactEmailController.text = _extractVCardField(raw, 'EMAIL') ?? '';
      } else if (lowerRaw.startsWith('geo:')) {
        _selectedType = QrDataType.geo;
        _generatedQrType = QrDataType.geo;
        _geoLatController.clear();
        _geoLngController.clear();
        _geoQueryController.clear();

        final body = raw.substring(4);
        final parts = body.split('?');
        final coordsPart = parts.first.split(';').first;
        final coords = coordsPart.split(',');
        if (coords.length >= 2) {
          final latStr = coords[0].trim();
          final lngStr = coords[1].trim();
          final isZeroCoords =
              (double.tryParse(latStr) == 0 && double.tryParse(lngStr) == 0) &&
              parts.length > 1;
          if (!isZeroCoords) {
            _geoLatController.text = latStr;
            _geoLngController.text = lngStr;
          }
        }
        if (parts.length > 1) {
          final queryString = parts.sublist(1).join('?');
          try {
            final queryParams = Uri.splitQueryString(
              queryString.replaceAll(' ', '+'),
            );
            _geoQueryController.text = queryParams['q'] ?? '';
          } catch (_) {
            _geoQueryController.text = queryString;
          }
        }
      } else if (lowerRaw.startsWith('http://') ||
          lowerRaw.startsWith('https://')) {
        _selectedType = QrDataType.url;
        _generatedQrType = QrDataType.url;
        _urlController.text = raw;
      } else {
        _selectedType = QrDataType.text;
        _generatedQrType = QrDataType.text;
        _textController.text = raw;
      }
    });
  }

  void _showScannedResultDialog(
    String scannedData, {
    bool wasDecrypted = false,
  }) {
    final detectedUrl = _extractHttpUrl(scannedData);

    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Row(
          children: [
            Icon(
              wasDecrypted
                  ? Icons.verified_user_outlined
                  : Icons.qr_code_scanner_rounded,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                wasDecrypted ? 'Код успішно розшифровано' : 'Код скановано',
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SelectableText(scannedData),
            if (detectedUrl != null) ...[
              const SizedBox(height: 16),
              FilledButton.tonalIcon(
                onPressed: () {
                  Navigator.of(dialogContext).pop();
                  _openSafeWebViewer(detectedUrl);
                },
                icon: const Icon(Icons.shield_outlined),
                label: const Text('Безпечний перегляд сторінки'),
              ),
            ],
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: scannedData));
              Navigator.of(dialogContext).pop();
              _showSnackBar('Скопійовано в буфер обміну');
            },
            icon: const Icon(Icons.copy_rounded),
            label: const Text('Копіювати'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Готово'),
          ),
        ],
      ),
    );
  }

  void _generateQrCode() {
    String data = '';

    switch (_selectedType) {
      case QrDataType.text:
        data = _textController.text.trim();
        if (data.isEmpty) {
          _showSnackBar('Введіть текст для створення QR-коду');
          return;
        }
        break;

      case QrDataType.url:
        String rawUrl = _urlController.text.trim();
        if (rawUrl.isEmpty) {
          _showSnackBar('Введіть посилання (URL)');
          return;
        }
        final lowerUrl = rawUrl.toLowerCase();
        if (!lowerUrl.startsWith('http://') &&
            !lowerUrl.startsWith('https://')) {
          rawUrl = 'https://$rawUrl';
        }
        data = rawUrl;
        break;

      case QrDataType.contact:
        final name = _contactNameController.text.trim();
        final phone = _contactPhoneController.text.trim();
        final email = _contactEmailController.text.trim();

        if (name.isEmpty && phone.isEmpty && email.isEmpty) {
          _showSnackBar('Заповніть хоча б одне поле контакту');
          return;
        }

        final buffer = StringBuffer('MECARD:');
        if (name.isNotEmpty) {
          buffer.write('N:${_escapeSpecialChars(name)};');
        }
        if (phone.isNotEmpty) {
          buffer.write('TEL:${_escapeSpecialChars(phone)};');
        }
        if (email.isNotEmpty) {
          buffer.write('EMAIL:${_escapeSpecialChars(email)};');
        }
        buffer.write(';');
        data = buffer.toString();
        break;

      case QrDataType.wifi:
        final ssid = _wifiSsidController.text.trim();
        final password = _wifiPasswordController.text;

        if (ssid.isEmpty) {
          _showSnackBar('Введіть назву мережі Wi-Fi (SSID)');
          return;
        }

        final escapedSsid = _escapeSpecialChars(ssid);
        final escapedPass = _escapeSpecialChars(password);
        final authType = _wifiEncryption.qrValue;

        if (_wifiEncryption == WifiEncryption.none) {
          data = 'WIFI:T:nopass;S:$escapedSsid;;';
        } else {
          data = 'WIFI:T:$authType;S:$escapedSsid;P:$escapedPass;;';
        }
        break;

      case QrDataType.geo:
        final rawLat = _geoLatController.text.trim().replaceAll(',', '.');
        final rawLng = _geoLngController.text.trim().replaceAll(',', '.');
        final query = _geoQueryController.text.trim();

        if (rawLat.isEmpty && rawLng.isEmpty && query.isEmpty) {
          _showSnackBar('Введіть координати або назву місця');
          return;
        }

        if (rawLat.isEmpty != rawLng.isEmpty) {
          _showSnackBar('Вкажіть обидві координати: і широту, і довготу');
          return;
        }

        double lat = 0;
        double lng = 0;
        if (rawLat.isNotEmpty && rawLng.isNotEmpty) {
          final parsedLat = double.tryParse(rawLat);
          final parsedLng = double.tryParse(rawLng);
          if (parsedLat == null ||
              parsedLng == null ||
              parsedLat < -90 ||
              parsedLat > 90 ||
              parsedLng < -180 ||
              parsedLng > 180) {
            _showSnackBar(
              'Некоректні координати (широта: -90..90, довгота: -180..180)',
            );
            return;
          }
          lat = parsedLat;
          lng = parsedLng;
        }

        final latFormatted = rawLat.isNotEmpty ? '$lat' : '0';
        final lngFormatted = rawLng.isNotEmpty ? '$lng' : '0';

        if (query.isNotEmpty) {
          data =
              'geo:$latFormatted,$lngFormatted?q=${Uri.encodeComponent(query)}';
        } else {
          data = 'geo:$latFormatted,$lngFormatted';
        }
        break;
    }

    if (_encryptWithPassword) {
      final encPassword = _encryptionPasswordController.text;
      if (encPassword.isEmpty) {
        _showSnackBar('Введіть пароль для шифрування QR-коду');
        return;
      }
      data = QrCryptoHelper.encrypt(data, encPassword);
    }

    final IconData? targetIcon = _centerIconMode == CenterIconMode.none
        ? null
        : (_centerIconMode == CenterIconMode.auto
              ? (_encryptWithPassword ? Icons.lock_rounded : _selectedType.icon)
              : _centerIconMode.icon);

    final errorCorrectionLevel = targetIcon != null
        ? QrErrorCorrectLevel.H
        : QrErrorCorrectLevel.M;
    final validation = QrValidator.validate(
      data: data,
      version: QrVersions.auto,
      errorCorrectionLevel: errorCorrectionLevel,
    );
    if (!validation.isValid) {
      if (validation.status == QrValidationStatus.contentTooLong) {
        _showSnackBar(
          'Обсяг даних завеликий для створення QR-коду (скоротіть текст або вимкніть іконку по центру)',
        );
      } else {
        _showSnackBar('Помилка генерації QR-коду: ${validation.error}');
      }
      return;
    }

    FocusScope.of(context).unfocus();
    setState(() {
      _generatedQrData = data;
      _generatedQrType = _selectedType;
      _generatedQrEncrypted = _encryptWithPassword;
    });
  }

  /// Рендерить QR-код у PNG-байти високої роздільної здатності з урахуванням кастомізації.
  Future<Uint8List> _renderQrPngBytes(String data) async {
    const double totalSize = 1024.0;
    const double padding = 64.0;
    const double qrSize = totalSize - padding * 2;

    final centerIcon = _effectiveCenterIcon;
    final errorCorrectionLevel = centerIcon != null
        ? QrErrorCorrectLevel.H
        : QrErrorCorrectLevel.M;

    final validation = QrValidator.validate(
      data: data,
      version: QrVersions.auto,
      errorCorrectionLevel: errorCorrectionLevel,
    );
    if (!validation.isValid) {
      throw Exception(
        validation.status == QrValidationStatus.contentTooLong
            ? 'Дані занадто довгі для вибраного рівня корекції помилок'
            : 'Некоректні дані для генерації QR-коду',
      );
    }

    final recorder = ui.PictureRecorder();
    final canvas = Canvas(recorder);

    // Малюємо суцільний білий фон для коректного зчитування сканерами
    final bgPaint = Paint()..color = Colors.white;
    canvas.drawRect(
      const Rect.fromLTWH(0, 0, totalSize, totalSize),
      bgPaint,
    );

    canvas.save();
    canvas.translate(padding, padding);

    final painter = QrPainter.withQr(
      qr: validation.qrCode!,
      gapless: _dataModuleShape == QrDataModuleShape.square,
      eyeStyle: QrEyeStyle(
        eyeShape: _eyeShape,
        color: _qrColor,
      ),
      dataModuleStyle: QrDataModuleStyle(
        dataModuleShape: _dataModuleShape,
        color: _qrColor,
      ),
    );
    painter.paint(canvas, const Size(qrSize, qrSize));
    canvas.restore();

    // Якщо вибрано центральну іконку — малюємо її по центру зображення
    if (centerIcon != null) {
      const double badgeSize = 180.0;
      final badgeRect = RRect.fromRectAndRadius(
        Rect.fromCenter(
          center: const Offset(totalSize / 2, totalSize / 2),
          width: badgeSize,
          height: badgeSize,
        ),
        const Radius.circular(36),
      );

      canvas.drawRRect(badgeRect, Paint()..color = Colors.white);
      canvas.drawRRect(
        badgeRect,
        Paint()
          ..color = _qrColor
          ..style = PaintingStyle.stroke
          ..strokeWidth = 6,
      );

      final textPainter = TextPainter(
        textDirection: TextDirection.ltr,
        text: TextSpan(
          text: String.fromCharCode(centerIcon.codePoint),
          style: TextStyle(
            fontSize: 110,
            fontFamily: centerIcon.fontFamily,
            package: centerIcon.fontPackage,
            color: _qrColor,
          ),
        ),
      );
      textPainter.layout();
      textPainter.paint(
        canvas,
        Offset(
          (totalSize - textPainter.width) / 2,
          (totalSize - textPainter.height) / 2,
        ),
      );
    }

    final picture = recorder.endRecording();
    try {
      final image = await picture.toImage(totalSize.toInt(), totalSize.toInt());
      try {
        final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
        if (byteData == null) {
          throw Exception('Не вдалося сформувати PNG-зображення');
        }
        return byteData.buffer.asUint8List();
      } finally {
        image.dispose();
      }
    } finally {
      picture.dispose();
    }
  }

  /// Зберігає QR-код у галерею (Android / iOS).
  Future<void> _saveToGallery() async {
    final data = _generatedQrData;
    if (data == null || _isSaving) return;

    setState(() => _isSaving = true);
    try {
      final pngBytes = await _renderQrPngBytes(data);
      final hasAccess = await Gal.hasAccess();
      if (!hasAccess) {
        final granted = await Gal.requestAccess();
        if (!granted) {
          _showSnackBar('Немає дозволу на збереження в галерею');
          return;
        }
      }

      final fileName = 'qr_${DateTime.now().millisecondsSinceEpoch}';
      await Gal.putImageBytes(pngBytes, name: fileName);
      _showSnackBar('QR-код успішно збережено в галерею!');
    } catch (e) {
      _showSnackBar('Помилка збереження в галерею: $e');
    } finally {
      unawaited(AppStorageCleaner.clearTemporaryStorage());
      if (mounted) {
        setState(() => _isSaving = false);
      }
    }
  }

  /// Зберігає QR-код у вибрану користувачем теку (для ПК або файлової системи).
  Future<void> _saveToFolder() async {
    final data = _generatedQrData;
    if (data == null || _isSaving) return;

    setState(() => _isSaving = true);
    try {
      final pngBytes = await _renderQrPngBytes(data);
      final defaultFileName = 'qr_${DateTime.now().millisecondsSinceEpoch}.png';

      final savedUri = await FilePicker.saveFile(
        dialogTitle: 'Оберіть теку для збереження QR-коду',
        fileName: defaultFileName,
        bytes: pngBytes,
        mimeType: 'image/png',
        type: FileType.custom,
        allowedExtensions: ['png'],
      );

      if (savedUri == null) return; // Користувач скасував вибір

      final locationLabel = savedUri.isScheme('file')
          ? savedUri.toFilePath()
          : savedUri.toString();
      _showSnackBar('Збережено: $locationLabel');
    } catch (e) {
      _showSnackBar('Помилка збереження файлу: $e');
    } finally {
      unawaited(AppStorageCleaner.clearTemporaryStorage());
      if (mounted) {
        setState(() => _isSaving = false);
      }
    }
  }

  Future<void> _showStorageOptimizationDialog() async {
    final stats = await AppStorageCleaner.inspectTempStorage();
    if (!mounted) return;

    const isDebugBuild = kDebugMode;
    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.cleaning_services_outlined),
            SizedBox(width: 10),
            Expanded(child: Text('Пам’ять та оптимізація')),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Тимчасовий кеш додатку: ${AppStorageCleaner.formatBytes(stats.totalBytes)} (${stats.fileCount} файлів)',
                style: const TextStyle(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 8),
              const Text(
                'Додаток не накопичує особистих даних чи історії, а тимчасові файли від збереження зображень автоматично видаляються.',
                style: TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(dialogContext)
                      .colorScheme
                      .surfaceContainerHighest
                      .withAlpha(120),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  isDebugBuild
                      ? '⚠️ Зараз запущено Debug-збірку (режим розробки).\n'
                            'Саме через Debug-режим додаток займає ~180–200 МБ: він містить віртуальну машину Dart VM, JIT-компілятор для Hot Reload та бібліотеки одразу для 3 процесорних архітектур (arm64, armv7, x86_64).\n\n'
                            'Щоб зменшити розмір у 8–10 разів (~18–25 МБ), встановіть Release-збірку командою:\n'
                            'flutter build apk --release --split-per-abi'
                      : '✅ Запущено оптимізовану Release-збірку (мініфікація R8 та стиснення ресурсів активні).',
                  style: const TextStyle(fontSize: 12.5, height: 1.4),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Закрити'),
          ),
          FilledButton.tonalIcon(
            onPressed: () async {
              final freed = await AppStorageCleaner.clearTemporaryStorage();
              if (!dialogContext.mounted) return;
              Navigator.of(dialogContext).pop();
              _showSnackBar(
                'Кеш очищено (звільнено ${AppStorageCleaner.formatBytes(freed)})',
              );
            },
            icon: const Icon(Icons.delete_sweep_outlined, size: 18),
            label: const Text('Очистити кеш'),
          ),
        ],
      ),
    );
  }

  void _copyGeneratedData() {
    final data = _generatedQrData;
    if (data == null) return;
    Clipboard.setData(ClipboardData(text: data));
    _showSnackBar('Вміст QR-коду скопійовано в буфер обміну');
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Text(message),
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      );
  }

  /// Допоміжний віджет випадаючого списку без зміни Key під час закриття меню.
  Widget _buildStyledDropdown<T>({
    required String labelText,
    IconData? prefixIcon,
    required T value,
    required List<DropdownMenuItem<T>> items,
    required ValueChanged<T?> onChanged,
    bool isDense = false,
  }) {
    return InputDecorator(
      decoration: InputDecoration(
        labelText: labelText,
        prefixIcon: prefixIcon != null ? Icon(prefixIcon) : null,
        isDense: isDense,
        contentPadding: EdgeInsets.symmetric(
          horizontal: 14,
          vertical: isDense ? 10 : 12,
        ),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<T>(
          value: value,
          isDense: true,
          isExpanded: true,
          items: items,
          onChanged: onChanged,
        ),
      ),
    );
  }

  Widget _buildTypeSelector(ColorScheme colorScheme) {
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: QrDataType.values.map((type) {
        final isSelected = _selectedType == type;
        return ChoiceChip(
          showCheckmark: false,
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          avatar: Icon(
            type.icon,
            size: 18,
            color: isSelected
                ? colorScheme.onPrimaryContainer
                : colorScheme.onSurfaceVariant,
          ),
          label: Text(
            type.label,
            style: TextStyle(
              fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
            ),
          ),
          selected: isSelected,
          selectedColor: colorScheme.primaryContainer,
          onSelected: (_) {
            setState(() {
              _selectedType = type;
            });
          },
        );
      }).toList(),
    );
  }

  Widget _buildInputFields() {
    switch (_selectedType) {
      case QrDataType.text:
        return TextField(
          controller: _textController,
          maxLines: 3,
          decoration: const InputDecoration(
            labelText: 'Введіть текст',
            hintText: 'Будь-який текст або повідомлення...',
            prefixIcon: Icon(Icons.notes_rounded),
          ),
        );

      case QrDataType.url:
        return TextField(
          controller: _urlController,
          keyboardType: TextInputType.url,
          decoration: InputDecoration(
            labelText: 'Адреса сайту (URL)',
            hintText: 'https://example.com',
            prefixIcon: const Icon(Icons.language_rounded),
            suffixIcon: IconButton(
              onPressed: () => _openSafeWebViewer(_urlController.text),
              tooltip: 'Перевірити та відкрити у безпечному переглядачі',
              icon: const Icon(Icons.shield_outlined),
            ),
          ),
        );

      case QrDataType.contact:
        return Column(
          children: [
            TextField(
              controller: _contactNameController,
              decoration: const InputDecoration(
                labelText: "Ім'я та прізвище",
                prefixIcon: Icon(Icons.person_outline_rounded),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _contactPhoneController,
              keyboardType: TextInputType.phone,
              decoration: const InputDecoration(
                labelText: 'Номер телефону',
                hintText: '+380...',
                prefixIcon: Icon(Icons.phone_outlined),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _contactEmailController,
              keyboardType: TextInputType.emailAddress,
              decoration: const InputDecoration(
                labelText: 'Email (необов’язково)',
                prefixIcon: Icon(Icons.email_outlined),
              ),
            ),
          ],
        );

      case QrDataType.wifi:
        return Column(
          children: [
            TextField(
              controller: _wifiSsidController,
              decoration: const InputDecoration(
                labelText: 'Назва мережі (SSID)',
                prefixIcon: Icon(Icons.wifi_rounded),
              ),
            ),
            const SizedBox(height: 12),
            _buildStyledDropdown<WifiEncryption>(
              labelText: 'Тип захисту',
              prefixIcon: Icons.security_rounded,
              value: _wifiEncryption,
              items: WifiEncryption.values
                  .map(
                    (enc) => DropdownMenuItem(
                      value: enc,
                      child: Text(enc.label),
                    ),
                  )
                  .toList(),
              onChanged: (value) {
                if (value != null) {
                  setState(() {
                    _wifiEncryption = value;
                  });
                }
              },
            ),
            if (_wifiEncryption != WifiEncryption.none) ...[
              const SizedBox(height: 12),
              TextField(
                controller: _wifiPasswordController,
                obscureText: _obscureWifiPassword,
                decoration: InputDecoration(
                  labelText: 'Пароль мережі',
                  prefixIcon: const Icon(Icons.lock_outline_rounded),
                  suffixIcon: IconButton(
                    onPressed: () {
                      setState(() {
                        _obscureWifiPassword = !_obscureWifiPassword;
                      });
                    },
                    tooltip: _obscureWifiPassword
                        ? 'Показати пароль'
                        : 'Приховати пароль',
                    icon: Icon(
                      _obscureWifiPassword
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined,
                    ),
                  ),
                ),
              ),
            ],
          ],
        );

      case QrDataType.geo:
        return Column(
          children: [
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _geoLatController,
                    keyboardType: const TextInputType.numberWithOptions(
                      decimal: true,
                      signed: true,
                    ),
                    decoration: const InputDecoration(
                      labelText: 'Широта (Lat)',
                      hintText: '50.4501',
                      prefixIcon: Icon(Icons.my_location_rounded),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: TextField(
                    controller: _geoLngController,
                    keyboardType: const TextInputType.numberWithOptions(
                      decimal: true,
                      signed: true,
                    ),
                    decoration: const InputDecoration(
                      labelText: 'Довгота (Lng)',
                      hintText: '30.5234',
                      prefixIcon: Icon(Icons.explore_outlined),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _geoQueryController,
              decoration: const InputDecoration(
                labelText: 'Назва місця або адреса (необов’язково)',
                hintText: 'Київ, Майдан Незалежності',
                prefixIcon: Icon(Icons.place_outlined),
              ),
            ),
          ],
        );
    }
  }

  Widget _buildEncryptionSection(ColorScheme colorScheme) {
    return Container(
      decoration: BoxDecoration(
        color: _encryptWithPassword
            ? colorScheme.primaryContainer.withAlpha(70)
            : colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: _encryptWithPassword
              ? colorScheme.primary.withAlpha(140)
              : colorScheme.outlineVariant,
        ),
      ),
      child: Column(
        children: [
          SwitchListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 14),
            secondary: Icon(
              _encryptWithPassword
                  ? Icons.lock_rounded
                  : Icons.lock_open_rounded,
              color: _encryptWithPassword
                  ? colorScheme.primary
                  : colorScheme.onSurfaceVariant,
            ),
            title: const Text(
              'Зашифрувати паролем',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
            ),
            subtitle: const Text(
              'Вміст можна буде прочитати лише ввівши пароль у додатку',
              style: TextStyle(fontSize: 12),
            ),
            value: _encryptWithPassword,
            onChanged: (value) {
              setState(() {
                _encryptWithPassword = value;
              });
            },
          ),
          if (_encryptWithPassword)
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 4, 14, 14),
              child: TextField(
                controller: _encryptionPasswordController,
                obscureText: _obscureEncryptionPassword,
                decoration: InputDecoration(
                  labelText: 'Пароль для захисту QR-коду',
                  hintText: 'Введіть надійний пароль...',
                  prefixIcon: const Icon(Icons.key_rounded),
                  suffixIcon: IconButton(
                    onPressed: () {
                      setState(() {
                        _obscureEncryptionPassword =
                            !_obscureEncryptionPassword;
                      });
                    },
                    tooltip: _obscureEncryptionPassword
                        ? 'Показати пароль'
                        : 'Приховати пароль',
                    icon: Icon(
                      _obscureEncryptionPassword
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined,
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildInputCard(ColorScheme colorScheme) {
    return Card(
      color: colorScheme.surfaceContainerLow,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(
                  Icons.tune_rounded,
                  size: 20,
                  color: colorScheme.primary,
                ),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Оберіть тип даних:',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                TextButton.icon(
                  onPressed: _clearCurrentInputs,
                  icon: const Icon(Icons.restart_alt_rounded, size: 18),
                  label: const Text('Очистити'),
                  style: TextButton.styleFrom(
                    visualDensity: VisualDensity.compact,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            _buildTypeSelector(colorScheme),
            const SizedBox(height: 8),
            Text(
              _selectedType.subtitle,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 16),
            _buildInputFields(),
            const SizedBox(height: 16),
            _buildEncryptionSection(colorScheme),
            const SizedBox(height: 20),
            FilledButton.icon(
              onPressed: _generateQrCode,
              icon: Icon(
                _encryptWithPassword
                    ? Icons.enhanced_encryption_rounded
                    : Icons.qr_code_2_rounded,
                size: 22,
              ),
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
              label: Text(
                _encryptWithPassword
                    ? 'Створити зашифрований QR-код'
                    : 'Створити QR-код',
                style: const TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCustomizationPanel(ColorScheme colorScheme) {
    return Card(
      color: colorScheme.surfaceContainerLow,
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        leading: Icon(Icons.palette_outlined, color: colorScheme.primary),
        title: const Text(
          'Кастомізація QR-коду',
          style: TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
        ),
        subtitle: Text(
          'Колір, форма точок та центральна іконка',
          style: TextStyle(fontSize: 12, color: colorScheme.onSurfaceVariant),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(20, 4, 20, 20),
        children: [
          const Align(
            alignment: Alignment.centerLeft,
            child: Text(
              'Колір коду:',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: kQrColorOptions.map((option) {
              final isSelected = _qrColor == option.color;
              return ChoiceChip(
                showCheckmark: false,
                label: Text(option.label),
                selected: isSelected,
                avatar: Container(
                  width: 18,
                  height: 18,
                  decoration: BoxDecoration(
                    color: option.color,
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white, width: 1.5),
                  ),
                  child: isSelected
                      ? const Icon(Icons.check, size: 11, color: Colors.white)
                      : null,
                ),
                onSelected: (_) {
                  setState(() => _qrColor = option.color);
                },
              );
            }).toList(),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _buildStyledDropdown<QrDataModuleShape>(
                  labelText: 'Форма точок',
                  value: _dataModuleShape,
                  isDense: true,
                  items: const [
                    DropdownMenuItem(
                      value: QrDataModuleShape.square,
                      child: Text('Квадратні'),
                    ),
                    DropdownMenuItem(
                      value: QrDataModuleShape.circle,
                      child: Text('Круглі'),
                    ),
                  ],
                  onChanged: (value) {
                    if (value != null) {
                      setState(() => _dataModuleShape = value);
                    }
                  },
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildStyledDropdown<QrEyeShape>(
                  labelText: 'Форма кутів',
                  value: _eyeShape,
                  isDense: true,
                  items: const [
                    DropdownMenuItem(
                      value: QrEyeShape.square,
                      child: Text('Квадратні'),
                    ),
                    DropdownMenuItem(
                      value: QrEyeShape.circle,
                      child: Text('Круглі'),
                    ),
                  ],
                  onChanged: (value) {
                    if (value != null) {
                      setState(() => _eyeShape = value);
                    }
                  },
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          _buildStyledDropdown<CenterIconMode>(
            labelText: 'Іконка по центру',
            prefixIcon: Icons.center_focus_strong_outlined,
            value: _centerIconMode,
            isDense: true,
            items: CenterIconMode.values
                .map(
                  (mode) => DropdownMenuItem(
                    value: mode,
                    child: Text(mode.label),
                  ),
                )
                .toList(),
            onChanged: (value) {
              if (value != null) {
                setState(() => _centerIconMode = value);
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildSaveActions() {
    final isCurrentlyEncrypted =
        _generatedQrData != null &&
        QrCryptoHelper.isEncrypted(_generatedQrData!);
    final detectedUrl =
        (!isCurrentlyEncrypted && _generatedQrData != null)
            ? _extractHttpUrl(_generatedQrData!)
            : null;

    if (_isDesktop) {
      return Wrap(
        spacing: 10,
        runSpacing: 8,
        alignment: WrapAlignment.center,
        children: [
          FilledButton.tonalIcon(
            onPressed: _isSaving ? null : _saveToFolder,
            icon: _isSaving
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.folder_open_rounded),
            label: const Text('Зберегти у вибрану теку'),
          ),
          if (detectedUrl != null)
            OutlinedButton.icon(
              onPressed: () => _openSafeWebViewer(detectedUrl),
              icon: const Icon(Icons.shield_outlined, size: 18),
              label: const Text('Безпечний перегляд'),
            ),
          if (isCurrentlyEncrypted)
            OutlinedButton.icon(
              onPressed: () =>
                  _showDecryptDialog(initialEncryptedData: _generatedQrData),
              icon: const Icon(Icons.lock_open_rounded, size: 18),
              label: const Text('Розшифрувати'),
            ),
          OutlinedButton.icon(
            onPressed: _copyGeneratedData,
            icon: const Icon(Icons.copy_rounded, size: 18),
            label: const Text('Копіювати дані'),
          ),
        ],
      );
    }

    return Wrap(
      spacing: 10,
      runSpacing: 8,
      alignment: WrapAlignment.center,
      children: [
        FilledButton.tonalIcon(
          onPressed: _isSaving ? null : _saveToGallery,
          icon: const Icon(Icons.photo_library_outlined),
          label: const Text('В галерею'),
        ),
        OutlinedButton.icon(
          onPressed: _isSaving ? null : _saveToFolder,
          icon: const Icon(Icons.folder_open_rounded),
          label: const Text('У теку'),
        ),
        if (detectedUrl != null)
          OutlinedButton.icon(
            onPressed: () => _openSafeWebViewer(detectedUrl),
            icon: const Icon(Icons.shield_outlined, size: 18),
            label: const Text('Безпечний перегляд'),
          ),
        if (isCurrentlyEncrypted)
          OutlinedButton.icon(
            onPressed: () =>
                _showDecryptDialog(initialEncryptedData: _generatedQrData),
            icon: const Icon(Icons.lock_open_rounded, size: 18),
            label: const Text('Розшифрувати'),
          ),
        IconButton.outlined(
          onPressed: _copyGeneratedData,
          tooltip: 'Копіювати вміст',
          icon: const Icon(Icons.copy_rounded, size: 18),
        ),
      ],
    );
  }

  Widget _buildQrResultCard(ColorScheme colorScheme) {
    final qrData = _generatedQrData;
    if (qrData == null) {
      return Card(
        color: colorScheme.surfaceContainerLow,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 40, horizontal: 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.qr_code_2_rounded,
                size: 72,
                color: colorScheme.outlineVariant,
              ),
              const SizedBox(height: 12),
              Text(
                'QR-код ще не створено',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Заповніть поля та натисніть «Створити QR-код»',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      );
    }

    final centerIcon = _effectiveCenterIcon;
    final errorCorrectionLevel = centerIcon != null
        ? QrErrorCorrectLevel.H
        : QrErrorCorrectLevel.M;
    final isValidQr = QrValidator.validate(
      data: qrData,
      version: QrVersions.auto,
      errorCorrectionLevel: errorCorrectionLevel,
    ).isValid;
    final activeType = _generatedQrType ?? _selectedType;

    return Card(
      color: colorScheme.surfaceContainerLow,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Wrap(
              spacing: 8,
              runSpacing: 6,
              alignment: WrapAlignment.center,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(activeType.icon, size: 18, color: colorScheme.primary),
                    const SizedBox(width: 6),
                    Text(
                      'Тип: ${activeType.label}',
                      style: TextStyle(
                        fontWeight: FontWeight.w600,
                        color: colorScheme.primary,
                      ),
                    ),
                  ],
                ),
                if (_generatedQrEncrypted)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: colorScheme.tertiaryContainer,
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.lock_rounded,
                          size: 14,
                          color: colorScheme.onTertiaryContainer,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'Зашифровано',
                          style: TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                            color: colorScheme.onTertiaryContainer,
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withAlpha(20),
                    blurRadius: 16,
                    offset: const Offset(0, 6),
                  ),
                ],
              ),
              child: Stack(
                alignment: Alignment.center,
                children: [
                  QrImageView(
                    data: qrData,
                    version: QrVersions.auto,
                    size: 220,
                    backgroundColor: Colors.white,
                    errorCorrectionLevel: errorCorrectionLevel,
                    gapless: _dataModuleShape == QrDataModuleShape.square,
                    eyeStyle: QrEyeStyle(
                      eyeShape: _eyeShape,
                      color: _qrColor,
                    ),
                    dataModuleStyle: QrDataModuleStyle(
                      dataModuleShape: _dataModuleShape,
                      color: _qrColor,
                    ),
                    errorStateBuilder: (context, error) => const Center(
                      child: Padding(
                        padding: EdgeInsets.all(12),
                        child: Text(
                          'Дані занадто довгі для відображення QR-коду (вимкніть центральну іконку або скоротіть текст)',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: Colors.red, fontSize: 12),
                        ),
                      ),
                    ),
                  ),
                  if (centerIcon != null && isValidQr)
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: _qrColor,
                          width: 2,
                        ),
                      ),
                      child: Icon(
                        centerIcon,
                        color: _qrColor,
                        size: 26,
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: colorScheme.surfaceContainerHighest.withAlpha(120),
                borderRadius: BorderRadius.circular(12),
              ),
              child: SelectableText(
                qrData,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                ),
              ),
            ),
            const SizedBox(height: 18),
            if (isValidQr) _buildSaveActions(),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        centerTitle: false,
        titleSpacing: 16,
        title: const Row(
          children: [
            Icon(Icons.qr_code_rounded, size: 22),
            SizedBox(width: 8),
            Flexible(
              child: Text(
                'Генератор QR-кодів',
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
              ),
            ),
          ],
        ),
        backgroundColor: colorScheme.surface,
        surfaceTintColor: colorScheme.surfaceTint,
        actions: [
          IconButton(
            visualDensity: VisualDensity.compact,
            onPressed: () => _showDecryptDialog(),
            tooltip: 'Розшифрувати QR-код паролем',
            icon: const Icon(Icons.lock_open_rounded),
          ),
          IconButton(
            visualDensity: VisualDensity.compact,
            onPressed: _showStorageOptimizationDialog,
            tooltip: 'Очищення кешу та пам’яті',
            icon: const Icon(Icons.cleaning_services_outlined),
          ),
          if (widget.onToggleTheme != null)
            IconButton(
              visualDensity: VisualDensity.compact,
              onPressed: widget.onToggleTheme,
              tooltip: isDark ? 'Світла тема' : 'Темна тема',
              icon: Icon(
                isDark ? Icons.light_mode_outlined : Icons.dark_mode_outlined,
              ),
            ),
          if (_isMobile)
            Padding(
              padding: const EdgeInsets.only(right: 4),
              child: IconButton(
                visualDensity: VisualDensity.compact,
                onPressed: _openScanner,
                tooltip: 'Сканувати QR-код',
                icon: const Icon(Icons.qr_code_scanner_rounded),
              ),
            ),
        ],
      ),
      floatingActionButton: _isMobile
          ? FloatingActionButton.extended(
              onPressed: _openScanner,
              tooltip: 'Увімкнути камеру для сканування',
              icon: const Icon(Icons.qr_code_scanner_rounded),
              label: const Text('Сканувати'),
            )
          : null,
      floatingActionButtonLocation: FloatingActionButtonLocation.endFloat,
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final isWide = constraints.maxWidth >= 860;

            if (isWide) {
              return Center(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(24),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 1040),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 6,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              _buildInputCard(colorScheme),
                              const SizedBox(height: 16),
                              _buildCustomizationPanel(colorScheme),
                            ],
                          ),
                        ),
                        const SizedBox(width: 24),
                        Expanded(
                          flex: 5,
                          child: _buildQrResultCard(colorScheme),
                        ),
                      ],
                    ),
                  ),
                ),
              );
            }

            return Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 88),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 520),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildInputCard(colorScheme),
                      const SizedBox(height: 14),
                      _buildCustomizationPanel(colorScheme),
                      if (_generatedQrData != null) ...[
                        const SizedBox(height: 20),
                        _buildQrResultCard(colorScheme),
                      ],
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

/// Окремий StatefulWidget для діалогу розшифрування, щоб контролери
/// коректно звільнялися лише після повного завершення анімації закриття діалогу.
class _DecryptQrDialog extends StatefulWidget {
  final String initialEncryptedData;
  final bool lockEncryptedField;

  const _DecryptQrDialog({
    required this.initialEncryptedData,
    required this.lockEncryptedField,
  });

  @override
  State<_DecryptQrDialog> createState() => _DecryptQrDialogState();
}

class _DecryptQrDialogState extends State<_DecryptQrDialog> {
  late final TextEditingController _codeController;
  final TextEditingController _passwordController = TextEditingController();
  bool _obscurePassword = true;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _codeController = TextEditingController(text: widget.initialEncryptedData);
  }

  @override
  void dispose() {
    _codeController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _attemptDecrypt() {
    final encryptedText = _codeController.text.trim();
    final password = _passwordController.text;

    if (encryptedText.isEmpty) {
      setState(() {
        _errorMessage = 'Вставте зашифрований код (QRCENC1:...)';
      });
      return;
    }
    if (!QrCryptoHelper.isEncrypted(encryptedText)) {
      setState(() {
        _errorMessage =
            'Цей код не є зашифрованим (відсутній префікс QRCENC1:)';
      });
      return;
    }
    if (password.isEmpty) {
      setState(() {
        _errorMessage = 'Введіть пароль для розшифрування';
      });
      return;
    }

    final decrypted = QrCryptoHelper.decrypt(encryptedText, password);
    if (decrypted == null) {
      setState(() {
        _errorMessage = 'Невірний пароль або пошкоджений код';
      });
      return;
    }

    Navigator.of(context).pop(decrypted);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Row(
        children: [
          Icon(Icons.lock_open_rounded),
          SizedBox(width: 10),
          Expanded(child: Text('Розшифрувати QR-код')),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Цей QR-код захищено паролем. Введіть пароль, щоб переглянути його вміст:',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 14),
            if (!widget.lockEncryptedField) ...[
              TextField(
                controller: _codeController,
                maxLines: 2,
                decoration: const InputDecoration(
                  labelText: 'Зашифрований рядок (QRCENC1:...)',
                  prefixIcon: Icon(Icons.qr_code_rounded),
                ),
              ),
              const SizedBox(height: 12),
            ],
            TextField(
              controller: _passwordController,
              obscureText: _obscurePassword,
              autofocus: true,
              onSubmitted: (_) => _attemptDecrypt(),
              decoration: InputDecoration(
                labelText: 'Пароль розшифрування',
                prefixIcon: const Icon(Icons.key_rounded),
                errorText: _errorMessage,
                suffixIcon: IconButton(
                  onPressed: () {
                    setState(() {
                      _obscurePassword = !_obscurePassword;
                    });
                  },
                  icon: Icon(
                    _obscurePassword
                        ? Icons.visibility_outlined
                        : Icons.visibility_off_outlined,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Скасувати'),
        ),
        FilledButton.icon(
          onPressed: _attemptDecrypt,
          icon: const Icon(Icons.lock_open_rounded, size: 18),
          label: const Text('Розшифрувати'),
        ),
      ],
    );
  }
}

/// Вбудований безпечний переглядач веб-сторінок (Safe Reader & Security Inspector).
/// Завантажує сторінку у контрольованій пісочниці без виконання JavaScript,
/// відстежує приховані редиректи, перевіряє SSL-сертифікат та фішингові ознаки.
class SafeWebViewerPage extends StatefulWidget {
  final String initialUrl;

  const SafeWebViewerPage({super.key, required this.initialUrl});

  @override
  State<SafeWebViewerPage> createState() => _SafeWebViewerPageState();
}

class _SafeWebViewerPageState extends State<SafeWebViewerPage> {
  late final TextEditingController _urlBarController;
  final List<String> _history = [];
  bool _isLoading = false;
  String? _errorMessage;
  SafePageAnalysis? _analysis;
  int _selectedTab = 0; // 0 = Читання, 1 = Посилання, 2 = Технічні дані

  @override
  void initState() {
    super.initState();
    _urlBarController = TextEditingController(text: widget.initialUrl);
    _loadUrl(widget.initialUrl);
  }

  @override
  void dispose() {
    _urlBarController.dispose();
    super.dispose();
  }

  Future<void> _loadUrl(String rawUrl, {bool addToHistory = true}) async {
    var target = rawUrl.trim();
    if (target.isEmpty) return;
    if (!target.toLowerCase().startsWith('http://') &&
        !target.toLowerCase().startsWith('https://')) {
      target = 'https://$target';
    }

    final initialUri = Uri.tryParse(target);
    if (initialUri == null || initialUri.host.isEmpty) {
      setState(() {
        _errorMessage = 'Некоректний формат веб-адреси: $target';
        _isLoading = false;
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _urlBarController.text = target;
    });

    if (addToHistory && (_history.isEmpty || _history.last != target)) {
      _history.add(target);
    }

    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10)
      ..userAgent = 'SafeQrReader/1.0 (Flutter Security Sandbox; No-JS)';

    try {
      final redirectChain = <String>[initialUri.toString()];
      var currentUri = initialUri;
      HttpClientResponse? response;

      for (int hop = 0; hop < 6; hop++) {
        final request = await client
            .getUrl(currentUri)
            .timeout(const Duration(seconds: 10));
        request.followRedirects = false;
        request.headers.set(
          HttpHeaders.acceptHeader,
          'text/html,application/xhtml+xml,text/plain,application/json;q=0.9,*/*;q=0.5',
        );

        final res = await request.close().timeout(const Duration(seconds: 10));
        if (res.isRedirect && res.headers.value(HttpHeaders.locationHeader) != null) {
          final loc = res.headers.value(HttpHeaders.locationHeader)!;
          await res.drain<void>();
          currentUri = currentUri.resolve(loc);
          redirectChain.add(currentUri.toString());
          continue;
        }
        response = res;
        break;
      }

      if (response == null) {
        throw Exception('Забагато перенаправлень (понад 6 редиректів поспіль)');
      }

      final contentType =
          response.headers.contentType?.toString() ?? 'невідомо';
      final mime = response.headers.contentType?.mimeType.toLowerCase() ?? '';

      final headersMap = <String, String>{};
      response.headers.forEach((name, values) {
        headersMap[name] = values.join(', ');
      });

      final cert = response.certificate;
      final securityEval = SafeWebInspector.evaluateUriSecurity(
        currentUri,
        redirectChain: redirectChain,
      );
      final securityNotes = List<String>.from(securityEval.notes);
      var riskLevel = securityEval.level;

      // Перевіряємо тип вмісту: чи не намагається сторінка завантажити бінарний файл
      final isTextContent =
          mime.isEmpty ||
          mime.startsWith('text/') ||
          mime.contains('html') ||
          mime.contains('json') ||
          mime.contains('xml') ||
          mime.contains('javascript');

      if (!isTextContent) {
        securityNotes.add(
          'Завантаження зупинено пісочницею: сервер повернув нетекстовий файл ($contentType). У безпечному режимі автоматичне скачування файлів заблоковано.',
        );
        if (riskLevel == UrlRiskLevel.safe) {
          riskLevel = UrlRiskLevel.warning;
        }

        await response.drain<void>();
        if (!mounted) return;
        setState(() {
          _analysis = SafePageAnalysis(
            originalUrl: initialUri.toString(),
            finalUrl: currentUri.toString(),
            redirectChain: redirectChain,
            riskLevel: riskLevel,
            securityNotes: securityNotes,
            statusCode: response!.statusCode,
            contentType: contentType,
            pageTitle: currentUri.host,
            metaDescription: '',
            textBlocks: [
              'Сервер повернув бінарний або медіа-ресурс ($contentType). Заради вашої безпеки автоматичне завантаження файлів вимкнено.',
            ],
            links: const [],
            rawSource: '',
            responseHeaders: headersMap,
            certIssuer: cert?.issuer,
            certSubject: cert?.subject,
            certValidUntil: cert?.endValidity,
          );
          _urlBarController.text = currentUri.toString();
          _isLoading = false;
        });
        return;
      }

      // Читаємо максимум 512 КБ текстових даних
      const maxBytes = 512 * 1024;
      final bytesBuilder = BytesBuilder(copy: false);
      await for (final chunk in response) {
        if (bytesBuilder.length + chunk.length > maxBytes) {
          final remaining = maxBytes - bytesBuilder.length;
          if (remaining > 0) {
            bytesBuilder.add(chunk.sublist(0, remaining));
          }
          break;
        }
        bytesBuilder.add(chunk);
      }

      final rawBytes = bytesBuilder.takeBytes();
      final bodyText = utf8.decode(rawBytes, allowMalformed: true);
      final parsed = SafeWebInspector.parseHtmlForSafeReading(
        bodyText,
        currentUri,
      );

      if (!mounted) return;
      setState(() {
        _analysis = SafePageAnalysis(
          originalUrl: initialUri.toString(),
          finalUrl: currentUri.toString(),
          redirectChain: redirectChain,
          riskLevel: riskLevel,
          securityNotes: securityNotes,
          statusCode: response!.statusCode,
          contentType: contentType,
          pageTitle: parsed.title.isNotEmpty ? parsed.title : currentUri.host,
          metaDescription: parsed.description,
          textBlocks: parsed.blocks,
          links: parsed.links,
          rawSource: bodyText.length > 20000
              ? '${bodyText.substring(0, 20000)}\n\n... [скорочено]'
              : bodyText,
          responseHeaders: headersMap,
          certIssuer: cert?.issuer,
          certSubject: cert?.subject,
          certValidUntil: cert?.endValidity,
        );
        _urlBarController.text = currentUri.toString();
        _isLoading = false;
      });
    } catch (e) {
      // Навіть якщо сервер недоступний — все одно показуємо евристичний звіт безпеки самої адреси
      final fallbackEval = SafeWebInspector.evaluateUriSecurity(initialUri);
      if (!mounted) return;
      setState(() {
        _errorMessage = 'Не вдалося завантажити сторінку: $e';
        _analysis = SafePageAnalysis(
          originalUrl: initialUri.toString(),
          finalUrl: initialUri.toString(),
          redirectChain: [initialUri.toString()],
          riskLevel: fallbackEval.level,
          securityNotes: fallbackEval.notes,
          statusCode: null,
          contentType: 'недоступно',
          pageTitle: initialUri.host,
          metaDescription: '',
          textBlocks: const [],
          links: const [],
          rawSource: '',
          responseHeaders: const {},
        );
        _isLoading = false;
      });
    } finally {
      client.close(force: true);
    }
  }

  void _goBackInHistory() {
    if (_history.length <= 1) return;
    _history.removeLast();
    final previous = _history.last;
    _loadUrl(previous, addToHistory: false);
  }

  Widget _buildSecurityBanner(SafePageAnalysis analysis, ColorScheme scheme) {
    final risk = analysis.riskLevel;
    return Card(
      color: risk.color.withAlpha(22),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: risk.color.withAlpha(120), width: 1.5),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(risk.icon, color: risk.color, size: 24),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Аналіз безпеки: ${risk.label}',
                    style: TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 15,
                      color: risk.color,
                    ),
                  ),
                ),
                if (analysis.statusCode != null)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 3,
                    ),
                    decoration: BoxDecoration(
                      color: scheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      'HTTP ${analysis.statusCode}',
                      style: const TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Пісочниця активна: JavaScript, сторонні трекери, cookies та автозавантаження файлів заблоковано.',
              style: TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            ...analysis.securityNotes.map(
              (note) => Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('• ', style: TextStyle(fontWeight: FontWeight.bold)),
                    Expanded(
                      child: Text(note, style: const TextStyle(fontSize: 12.5)),
                    ),
                  ],
                ),
              ),
            ),
            if (analysis.redirectChain.length > 1) ...[
              const Divider(height: 18),
              const Text(
                'Ланцюжок перенаправлень (редиректів):',
                style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              ...analysis.redirectChain.asMap().entries.map(
                (entry) => Text(
                  '${entry.key + 1}. ${entry.value}',
                  style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildReaderTab(SafePageAnalysis analysis, ColorScheme scheme) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _buildSecurityBanner(analysis, scheme),
        if (_errorMessage != null) ...[
          const SizedBox(height: 12),
          Card(
            color: scheme.errorContainer,
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Text(
                _errorMessage!,
                style: TextStyle(color: scheme.onErrorContainer, fontSize: 13),
              ),
            ),
          ),
        ],
        const SizedBox(height: 14),
        Card(
          color: scheme.surfaceContainerLow,
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  analysis.pageTitle,
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                SelectableText(
                  analysis.finalUrl,
                  style: TextStyle(
                    fontSize: 12,
                    color: scheme.primary,
                    fontFamily: 'monospace',
                  ),
                ),
                if (analysis.metaDescription.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: scheme.surfaceContainerHighest.withAlpha(100),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      analysis.metaDescription,
                      style: const TextStyle(
                        fontSize: 13,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                  ),
                ],
                const Divider(height: 24),
                if (analysis.textBlocks.isEmpty)
                  Text(
                    'Текстовий вміст сторінки порожній або сторінка потребує клієнтського рендерингу.',
                    style: TextStyle(color: scheme.onSurfaceVariant),
                  )
                else
                  ...analysis.textBlocks.map((block) {
                    if (block.startsWith('## ')) {
                      return Padding(
                        padding: const EdgeInsets.only(top: 14, bottom: 6),
                        child: SelectableText(
                          block.substring(3),
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      );
                    }
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: SelectableText(
                        block,
                        style: const TextStyle(fontSize: 14, height: 1.45),
                      ),
                    );
                  }),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildLinksTab(SafePageAnalysis analysis, ColorScheme scheme) {
    if (analysis.links.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('На сторінці не знайдено зовнішніх або внутрішніх посилань.'),
        ),
      );
    }

    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemCount: analysis.links.length,
      separatorBuilder: (_, _) => const SizedBox(height: 8),
      itemBuilder: (context, index) {
        final item = analysis.links[index];
        return Card(
          color: scheme.surfaceContainerLow,
          child: ListTile(
            leading: Icon(Icons.link_rounded, color: scheme.primary),
            title: Text(
              item.text,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
            ),
            subtitle: Text(
              item.url,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
            trailing: IconButton(
              icon: const Icon(Icons.copy_rounded, size: 18),
              tooltip: 'Скопіювати посилання',
              onPressed: () {
                Clipboard.setData(ClipboardData(text: item.url));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Посилання скопійовано'),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
            ),
            onTap: () {
              setState(() => _selectedTab = 0);
              _loadUrl(item.url);
            },
          ),
        );
      },
    );
  }

  Widget _buildTechnicalTab(SafePageAnalysis analysis, ColorScheme scheme) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (analysis.certSubject != null || analysis.certIssuer != null)
          Card(
            color: scheme.surfaceContainerLow,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'SSL / TLS сертифікат сервера:',
                    style: TextStyle(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 8),
                  if (analysis.certSubject != null)
                    Text('Суб’єкт: ${analysis.certSubject}', style: const TextStyle(fontSize: 12.5)),
                  if (analysis.certIssuer != null)
                    Text('Видавець: ${analysis.certIssuer}', style: const TextStyle(fontSize: 12.5)),
                  if (analysis.certValidUntil != null)
                    Text('Дійсний до: ${analysis.certValidUntil}', style: const TextStyle(fontSize: 12.5)),
                ],
              ),
            ),
          ),
        const SizedBox(height: 12),
        Card(
          color: scheme.surfaceContainerLow,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'HTTP-заголовки відповіді:',
                  style: TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 8),
                if (analysis.responseHeaders.isEmpty)
                  const Text('Немає даних заголовків')
                else
                  ...analysis.responseHeaders.entries.map(
                    (e) => Padding(
                      padding: const EdgeInsets.only(bottom: 4),
                      child: SelectableText(
                        '${e.key}: ${e.value}',
                        style: const TextStyle(
                          fontSize: 12,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          color: scheme.surfaceContainerLow,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Вихідний код сторінки (HTML):',
                  style: TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 8),
                SelectableText(
                  analysis.rawSource.isNotEmpty
                      ? analysis.rawSource
                      : 'Вихідний код відсутній',
                  style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace'),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final analysis = _analysis;

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 8,
        title: const Row(
          children: [
            Icon(Icons.shield_outlined, size: 20),
            SizedBox(width: 8),
            Flexible(
              child: Text(
                'Безпечний переглядач',
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700),
              ),
            ),
          ],
        ),
        actions: [
          if (_history.length > 1)
            IconButton(
              onPressed: _isLoading ? null : _goBackInHistory,
              tooltip: 'Попередня сторінка',
              icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
            ),
          IconButton(
            onPressed: _isLoading
                ? null
                : () => _loadUrl(_urlBarController.text, addToHistory: false),
            tooltip: 'Оновити',
            icon: const Icon(Icons.refresh_rounded),
          ),
          IconButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _urlBarController.text));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Адресу скопійовано в буфер обміну'),
                  behavior: SnackBarBehavior.floating,
                ),
              );
            },
            tooltip: 'Скопіювати URL',
            icon: const Icon(Icons.copy_rounded, size: 19),
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 10),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _urlBarController,
                    keyboardType: TextInputType.url,
                    onSubmitted: (val) => _loadUrl(val),
                    decoration: const InputDecoration(
                      hintText: 'https://...',
                      prefixIcon: Icon(Icons.public_rounded, size: 20),
                      isDense: true,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton(
                  onPressed: _isLoading
                      ? null
                      : () => _loadUrl(_urlBarController.text),
                  child: const Text('Перейти'),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: SegmentedButton<int>(
              showSelectedIcon: false,
              segments: [
                const ButtonSegment(
                  value: 0,
                  icon: Icon(Icons.article_outlined, size: 18),
                  label: Text('Читання'),
                ),
                ButtonSegment(
                  value: 1,
                  icon: const Icon(Icons.link_rounded, size: 18),
                  label: Text(
                    'Посилання${analysis != null ? ' (${analysis.links.length})' : ''}',
                  ),
                ),
                const ButtonSegment(
                  value: 2,
                  icon: Icon(Icons.code_rounded, size: 18),
                  label: Text('Код і SSL'),
                ),
              ],
              selected: {_selectedTab},
              onSelectionChanged: (selection) {
                setState(() => _selectedTab = selection.first);
              },
            ),
          ),
          const SizedBox(height: 8),
          if (_isLoading) const LinearProgressIndicator(),
          Expanded(
            child: analysis == null
                ? const Center(child: CircularProgressIndicator())
                : IndexedStack(
                    index: _selectedTab,
                    children: [
                      _buildReaderTab(analysis, scheme),
                      _buildLinksTab(analysis, scheme),
                      _buildTechnicalTab(analysis, scheme),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

/// Екран сканування QR-коду за допомогою камери мобільного пристрою.
class QrScannerPage extends StatefulWidget {
  const QrScannerPage({super.key});

  @override
  State<QrScannerPage> createState() => _QrScannerPageState();
}

class _QrScannerPageState extends State<QrScannerPage> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );
  bool _hasScanned = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned || !mounted) return;

    for (final barcode in capture.barcodes) {
      final rawValue = barcode.rawValue;
      if (rawValue != null && rawValue.isNotEmpty) {
        _hasScanned = true;
        Navigator.of(context).pop(rawValue);
        break;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Сканування QR-коду'),
        actions: [
          ValueListenableBuilder<MobileScannerState>(
            valueListenable: _controller,
            builder: (context, state, _) {
              final isReady = state.isInitialized && state.isRunning;
              final torchAvailable =
                  isReady && state.torchState != TorchState.unavailable;
              final isTorchOn = state.torchState == TorchState.on;

              return Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    onPressed: torchAvailable
                        ? () => _controller.toggleTorch()
                        : null,
                    tooltip: 'Ліхтарик',
                    icon: Icon(isTorchOn ? Icons.flash_on : Icons.flash_off),
                  ),
                  IconButton(
                    onPressed: isReady
                        ? () => _controller.switchCamera()
                        : null,
                    tooltip: 'Змінити камеру',
                    icon: const Icon(Icons.cameraswitch),
                  ),
                ],
              );
            },
          ),
        ],
      ),
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(
                      Icons.videocam_off_outlined,
                      color: Colors.white70,
                      size: 56,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Не вдалося запустити камеру (${error.errorCode.name})',
                      textAlign: TextAlign.center,
                      style: const TextStyle(color: Colors.white, fontSize: 16),
                    ),
                  ],
                ),
              ),
            ),
          ),
          Center(
            child: Container(
              width: 250,
              height: 250,
              decoration: BoxDecoration(
                border: Border.all(color: Colors.white, width: 3),
                borderRadius: BorderRadius.circular(20),
              ),
            ),
          ),
          Positioned(
            bottom: 32,
            left: 24,
            right: 24,
            child: Center(
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: const Text(
                  'Наведіть камеру на QR-код',
                  style: TextStyle(color: Colors.white, fontSize: 14),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
