import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'package:qr_coder_test/main.dart';

void main() {
  testWidgets('QR code generator creates QR from text and geolocation input', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const MyApp());

    expect(find.text('Генератор QR-кодів'), findsOneWidget);
    expect(find.byType(QrImageView), findsNothing);

    // 1. Генерація з тексту
    await tester.enterText(find.byType(TextField).first, 'Привіт, світ!');
    await tester.tap(find.text('Створити QR-код'));
    await tester.pump();

    expect(find.byType(QrImageView), findsOneWidget);
    expect(find.text('Привіт, світ!'), findsWidgets);

    // 2. Перемикання на Геолокацію
    await tester.tap(find.text('Геолокація'));
    await tester.pump();

    await tester.enterText(
      find.widgetWithText(TextField, 'Широта (Lat)'),
      '50.4501',
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Довгота (Lng)'),
      '30.5234',
    );
    await tester.tap(find.text('Створити QR-код'));
    await tester.pump();

    expect(find.text('geo:50.4501,30.5234'), findsOneWidget);
  });
}
