# پروژه Reflex
## شماره‌های دانشجویی
400108911-حنانه مبلغ توحید
401100444-علی عبدلی مسینان
400109232-آرمان کشازرع

## توضیحات پیاده‌سازی

این پروژه شامل پیاده‌سازی کامل پروتکل Reflex در Xray-Core است:

- Step 1: ساختار اولیه و ثبت پروتکل
- Step 2: پیاده‌سازی Handshake ضمنی و احراز هویت با UUID
- Step 3: پیاده‌سازی Frame Structure و رمزنگاری ChaCha20-Poly1305
- Step 4: پیاده‌سازی Fallback به وب‌سرور و تشخیص با Peek
- Step 5: پیاده‌سازی Traffic Morphing پایه و کنترل Timing

## نحوه اجرا

```bash
cd xray-core
go build -o xray ./main
go test ./proxy/reflex/... -v

## چیه این پروژه؟

پروژه Reflex یک پروتکل پراکسی جدید برای Xray-Core هست که سعی می‌کنه مشکلات پروتکل‌های قبلی مثل VMess و VLESS رو حل کنه. هدف اصلی اینه که ترافیک پراکسی رو غیرقابل تشخیص کنیم - یعنی سانسورچی نتونه بفهمه که این ترافیک پراکسی هست.

## چیکار باید بکنید؟

شما باید پروتکل Reflex رو در Xray-Core پیاده‌سازی کنید. این کار در چند مرحله انجام می‌شه:

1. **مرحله 1**: ساختار اولیه پروتکل (پکیج، config، handler اولیه)
2. **مرحله 2**: پیاده‌سازی handshake و احراز هویت
3. **مرحله 3**: رمزنگاری و پردازش بسته‌ها
4. **مرحله 4**: fallback به وب‌سرور (مثل Trojan)
5. **مرحله 5**: قابلیت‌های پیشرفته (Traffic Morphing و ...)

## چطوری شروع کنید؟

1. اول [راه‌اندازی محیط](docs/setup.md) رو بخونید و Go و Git رو نصب کنید
2. ریپو Reflex رو کلون کنید (که شامل Xray-Core هست) و بیلد اولیه رو تست کنید
3. [پروتکل Reflex](docs/protocol.md) رو بخونید تا بفهمید چطوری کار می‌کنه
4. مرحله به مرحله پیش برید: [Step 1](docs/step1-basic.md) → [Step 2](docs/step2-handshake.md) → [Step 3](docs/step3-encryption.md) → [Step 4](docs/step4-fallback.md) → [Step 5](docs/step5-advanced.md)
5. [تست کنید](docs/testing.md) که همه چیز درست کار می‌کنه
6. [تحویل بدید](docs/submission.md) - یک برنچ بسازید و PR بزنید

## نمره‌دهی (120 نمره)

### پیاده‌سازی (80 نمره)
- **Step 1 - Basic Structure**: 10 نمره
- **Step 2 - Handshake**: 15 نمره
- **Step 3 - Encryption**: 15 نمره
- **Step 4 - Fallback**: 15 نمره
- **Step 5 - Advanced**: 20 نمره (15 نمره اجباری + 5 نمره امتیازی)

### تست‌ها (20 نمره)
- تست‌های واحد: 10 نمره
- تست‌های یکپارچگی: 10 نمره

### کد و مستندات (20 نمره)
- کیفیت کد و خوانایی: 10 نمره
- مستندات و کامنت‌ها: 10 نمره

جزئیات بیشتر در [فایل تحویل](docs/submission.md) هست.

## منابع

- [Xray-Core Repository](https://github.com/XTLS/Xray-core)
- [Go Documentation](https://go.dev/doc/)
- [Protocol Specification](docs/protocol.md)

## سوال دارید؟

اگر مشکلی پیش اومد یا سوالی دارید، اول [FAQ](docs/FAQ.md) رو چک کنید. اگر جوابتون رو پیدا نکردید، از من بپرسید
---

**موفق باشید!** 

