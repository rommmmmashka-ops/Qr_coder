import 'dart:io';
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

enum QrDataType {
  text('Текст', Icons.text_fields),
  url('URL', Icons.link),
  contact('Контакт', Icons.person),
  wifi('Wi-Fi', Icons.wifi),
  geo('Геолокація', Icons.location_on);

  final String label;
  final IconData icon;
  const QrDataType(this.label, this.icon);
}

enum WifiEncryption {
  wpa('WPA/WPA2', 'WPA'),
  wep('WEP', 'WEP'),
  none('Без пароля', 'nopass');

  final String label;
  final String qrValue;
  const WifiEncryption(this.label, this.qrValue);
}

enum CenterIconMode {
  none('Без іконки', null),
  auto('За типом даних', null),
  wifi('Wi-Fi', Icons.wifi),
  link('Посилання', Icons.language),
  person('Контакт', Icons.person),
  location('Локація', Icons.location_on),
  star('Зірка', Icons.star);

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
  QrColorOption('Чорний', Colors.black),
  QrColorOption('Індиго', Color(0xFF283593)),
  QrColorOption('Синій', Color(0xFF0D47A1)),
  QrColorOption('Зелений', Color(0xFF1B5E20)),
  QrColorOption('Бордовий', Color(0xFF880E4F)),
  QrColorOption('Фіолетовий', Color(0xFF4A148C)),
];

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Генератор QR-кодів',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: const QrGeneratorPage(),
    );
  }
}

class QrGeneratorPage extends StatefulWidget {
  const QrGeneratorPage({super.key});

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

  final _geoLatController = TextEditingController();
  final _geoLngController = TextEditingController();
  final _geoQueryController = TextEditingController();

  // Налаштування кастомізації QR-коду
  Color _qrColor = Colors.black;
  QrDataModuleShape _dataModuleShape = QrDataModuleShape.square;
  QrEyeShape _eyeShape = QrEyeShape.square;
  CenterIconMode _centerIconMode = CenterIconMode.auto;

  // Рядок даних, з якого генерується QR-код
  String? _generatedQrData;
  bool _isSaving = false;

  bool get _isDesktop =>
      !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);

  bool get _isMobile => !kIsWeb && (Platform.isAndroid || Platform.isIOS);

  IconData? get _effectiveCenterIcon {
    switch (_centerIconMode) {
      case CenterIconMode.none:
        return null;
      case CenterIconMode.auto:
        return _selectedType.icon;
      default:
        return _centerIconMode.icon;
    }
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
    return input
        .replaceAll(r'\:', ':')
        .replaceAll(r'\,', ',')
        .replaceAll(r'\;', ';')
        .replaceAll(r'\\', r'\');
  }

  String? _extractTagValue(String source, String tag) {
    final pattern = RegExp('$tag:((?:\\\\.|[^;])*)');
    final match = pattern.firstMatch(source);
    if (match == null) return null;
    return _unescapeSpecialChars(match.group(1) ?? '');
  }

  /// Відкриває екран камери для сканування QR-коду (на мобільних пристроях).
  Future<void> _openScanner() async {
    final scannedData = await Navigator.of(context).push<String>(
      MaterialPageRoute(
        builder: (context) => const QrScannerPage(),
      ),
    );

    if (scannedData == null || scannedData.isEmpty || !mounted) return;

    _applyScannedData(scannedData);
    _showScannedResultDialog(scannedData);
  }

  /// Розпізнає тип сканованого QR-коду та заповнює відповідні поля форми.
  void _applyScannedData(String raw) {
    setState(() {
      _generatedQrData = raw;

      if (raw.startsWith('WIFI:')) {
        _selectedType = QrDataType.wifi;
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
      } else if (raw.startsWith('MECARD:')) {
        _selectedType = QrDataType.contact;
        final body = raw.substring(7);
        _contactNameController.text = _extractTagValue(body, 'N') ?? '';
        _contactPhoneController.text = _extractTagValue(body, 'TEL') ?? '';
        _contactEmailController.text = _extractTagValue(body, 'EMAIL') ?? '';
      } else if (raw.toLowerCase().startsWith('geo:')) {
        _selectedType = QrDataType.geo;
        final uri = Uri.tryParse(raw);
        if (uri != null) {
          final coords = uri.path.split(',');
          if (coords.length >= 2) {
            _geoLatController.text = coords[0].trim();
            _geoLngController.text = coords[1].trim();
          }
          _geoQueryController.text = uri.queryParameters['q'] ?? '';
        }
      } else if (raw.startsWith('http://') || raw.startsWith('https://')) {
        _selectedType = QrDataType.url;
        _urlController.text = raw;
      } else {
        _selectedType = QrDataType.text;
        _textController.text = raw;
      }
    });
  }

  void _showScannedResultDialog(String scannedData) {
    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.qr_code_scanner),
            SizedBox(width: 8),
            Expanded(child: Text('Код скановано')),
          ],
        ),
        content: SelectableText(scannedData),
        actions: [
          TextButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: scannedData));
              Navigator.of(dialogContext).pop();
              _showSnackBar('Скопійовано в буфер обміну');
            },
            icon: const Icon(Icons.copy),
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
        if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
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

        // Формат MECARD для контактів
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

        // Стандартний формат WIFI:T:WPA;S:MyNetwork;P:MyPassword;;
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

        double lat = 0;
        double lng = 0;
        if (rawLat.isNotEmpty || rawLng.isNotEmpty) {
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

        if (query.isNotEmpty) {
          data = 'geo:$lat,$lng?q=${Uri.encodeComponent(query)}';
        } else {
          data = 'geo:$lat,$lng';
        }
        break;
    }

    FocusScope.of(context).unfocus();
    setState(() {
      _generatedQrData = data;
    });
  }

  /// Рендерить QR-код у PNG-байти високої роздільної здатності з урахуванням кастомізації.
  Future<Uint8List> _renderQrPngBytes(String data) async {
    const double totalSize = 1024.0;
    const double padding = 64.0;
    const double qrSize = totalSize - padding * 2;

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

    final centerIcon = _effectiveCenterIcon;
    final painter = QrPainter(
      data: data,
      version: QrVersions.auto,
      errorCorrectionLevel: centerIcon != null
          ? QrErrorCorrectLevel.H
          : QrErrorCorrectLevel.M,
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
    final image = await picture.toImage(totalSize.toInt(), totalSize.toInt());
    final byteData = await image.toByteData(format: ui.ImageByteFormat.png);

    if (byteData == null) {
      throw Exception('Не вдалося сформувати PNG-зображення');
    }
    return byteData.buffer.asUint8List();
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
      if (mounted) {
        setState(() => _isSaving = false);
      }
    }
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
      ),
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
            prefixIcon: Icon(Icons.notes),
          ),
        );

      case QrDataType.url:
        return TextField(
          controller: _urlController,
          keyboardType: TextInputType.url,
          decoration: const InputDecoration(
            labelText: 'Адреса сайту (URL)',
            hintText: 'https://example.com',
            prefixIcon: Icon(Icons.language),
          ),
        );

      case QrDataType.contact:
        return Column(
          children: [
            TextField(
              controller: _contactNameController,
              decoration: const InputDecoration(
                labelText: "Ім'я та прізвище",
                prefixIcon: Icon(Icons.person_outline),
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
                prefixIcon: Icon(Icons.wifi),
              ),
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<WifiEncryption>(
              initialValue: _wifiEncryption,
              decoration: const InputDecoration(
                labelText: 'Тип захисту',
                prefixIcon: Icon(Icons.security),
              ),
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
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Пароль мережі',
                  prefixIcon: Icon(Icons.lock_outline),
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
                      prefixIcon: Icon(Icons.my_location),
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

  Widget _buildCustomizationPanel() {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Theme.of(context).colorScheme.outlineVariant),
      ),
      child: ExpansionTile(
        leading: const Icon(Icons.palette_outlined),
        title: const Text(
          'Кастомізація QR-коду',
          style: TextStyle(fontWeight: FontWeight.w600),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          const Align(
            alignment: Alignment.centerLeft,
            child: Text('Колір коду:'),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: kQrColorOptions.map((option) {
              final isSelected = _qrColor == option.color;
              return ChoiceChip(
                label: Text(option.label),
                selected: isSelected,
                avatar: CircleAvatar(
                  backgroundColor: option.color,
                  radius: 8,
                ),
                onSelected: (_) {
                  setState(() => _qrColor = option.color);
                },
              );
            }).toList(),
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: DropdownButtonFormField<QrDataModuleShape>(
                  initialValue: _dataModuleShape,
                  decoration: const InputDecoration(
                    labelText: 'Форма точок',
                    isDense: true,
                  ),
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
                child: DropdownButtonFormField<QrEyeShape>(
                  initialValue: _eyeShape,
                  decoration: const InputDecoration(
                    labelText: 'Форма кутів',
                    isDense: true,
                  ),
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
          DropdownButtonFormField<CenterIconMode>(
            initialValue: _centerIconMode,
            decoration: const InputDecoration(
              labelText: 'Іконка по центру',
              prefixIcon: Icon(Icons.center_focus_strong_outlined),
              isDense: true,
            ),
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
    if (_isDesktop) {
      return OutlinedButton.icon(
        onPressed: _isSaving ? null : _saveToFolder,
        icon: _isSaving
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : const Icon(Icons.folder_open),
        label: const Text('Зберегти у вибрану теку'),
      );
    }

    return Wrap(
      spacing: 12,
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
          icon: const Icon(Icons.folder_open),
          label: const Text('У теку'),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final centerIcon = _effectiveCenterIcon;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Генератор QR-кодів'),
        centerTitle: true,
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          if (_isMobile)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: IconButton(
                onPressed: _openScanner,
                tooltip: 'Сканувати QR-код',
                icon: const Icon(Icons.qr_code_scanner),
              ),
            ),
        ],
      ),
      floatingActionButton: _isMobile
          ? FloatingActionButton.extended(
              onPressed: _openScanner,
              tooltip: 'Увімкнути камеру для сканування',
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Сканувати'),
            )
          : null,
      floatingActionButtonLocation: FloatingActionButtonLocation.endFloat,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 20, 20, 88),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 500),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'Оберіть тип даних:',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: QrDataType.values.map((type) {
                    final isSelected = _selectedType == type;
                    return ChoiceChip(
                      showCheckmark: false,
                      avatar: Icon(
                        type.icon,
                        size: 18,
                        color: isSelected
                            ? Theme.of(context).colorScheme.onSecondaryContainer
                            : Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                      label: Text(type.label),
                      selected: isSelected,
                      onSelected: (_) {
                        setState(() {
                          _selectedType = type;
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 20),
                _buildInputFields(),
                const SizedBox(height: 16),
                _buildCustomizationPanel(),
                const SizedBox(height: 20),
                FilledButton.icon(
                  onPressed: _generateQrCode,
                  icon: const Icon(Icons.qr_code_2),
                  label: const Padding(
                    padding: EdgeInsets.symmetric(vertical: 12),
                    child: Text(
                      'Створити QR-код',
                      style: TextStyle(fontSize: 16),
                    ),
                  ),
                ),
                const SizedBox(height: 28),
                if (_generatedQrData != null)
                  Card(
                    elevation: 2,
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Stack(
                              alignment: Alignment.center,
                              children: [
                                QrImageView(
                                  data: _generatedQrData!,
                                  version: QrVersions.auto,
                                  size: 220,
                                  backgroundColor: Colors.white,
                                  errorCorrectionLevel: centerIcon != null
                                      ? QrErrorCorrectLevel.H
                                      : QrErrorCorrectLevel.M,
                                  gapless:
                                      _dataModuleShape ==
                                      QrDataModuleShape.square,
                                  eyeStyle: QrEyeStyle(
                                    eyeShape: _eyeShape,
                                    color: _qrColor,
                                  ),
                                  dataModuleStyle: QrDataModuleStyle(
                                    dataModuleShape: _dataModuleShape,
                                    color: _qrColor,
                                  ),
                                ),
                                if (centerIcon != null)
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
                          const SizedBox(height: 12),
                          SelectableText(
                            _generatedQrData!,
                            textAlign: TextAlign.center,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                          const SizedBox(height: 16),
                          _buildSaveActions(),
                        ],
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
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
    if (_hasScanned) return;

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
          IconButton(
            onPressed: () => _controller.toggleTorch(),
            tooltip: 'Ліхтарик',
            icon: const Icon(Icons.flash_on),
          ),
          IconButton(
            onPressed: () => _controller.switchCamera(),
            tooltip: 'Змінити камеру',
            icon: const Icon(Icons.cameraswitch),
          ),
        ],
      ),
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
          ),
          Center(
            child: Container(
              width: 250,
              height: 250,
              decoration: BoxDecoration(
                border: Border.all(color: Colors.white, width: 3),
                borderRadius: BorderRadius.circular(16),
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
