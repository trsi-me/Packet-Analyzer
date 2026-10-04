# Packet Analyzer

## 1 ما هو المشروع

Packet Analyzer تطبيق ويب محلي يلتقط حزماً من واجهة شبكة على الجهاز، يخزّن ملخصاً لكل حزمة في SQLite، ويعرض جداول ورسوماً باللغة العربية مع تحديث فوري عبر Socket.IO.

الإصدار في الكود: `APP_VERSION = "1.0.0"` داخل `app.py`.

الخادم يستمع على `127.0.0.1:5000` فقط. التقاط الحزم يتم عبر Scapy على الواجهة التي يختارها المستخدم، ويحتاج على Windows برنامج Npcap حسب الدليل السابق. التعليق في `app.py` يذكر أن التحذير عن libpcap يُكتم، وأن التثبيت الفعلي لـ Npcap هو ما يتيح الالتقاط.

الاستخدام المقصود في الدليل السابق: ما يمر على جهازك وواجهة الشبكة التي تختارها.

## 2 لمن هذا المشروع

مشغّل على جهازه يفتح المتصفح محلياً. لا حسابات مستخدمين. على Windows دالة `is_windows_admin` تفحص هل العملية بصلاحية مسؤول، لأن الالتقاط قد يحتاج ذلك.

## 3 الميزات الفعلية

| الصفحة | المسار |
| --- | --- |
| رئيسية | `GET /` |
| الحزم | `GET /packets` |
| التحليل | `GET /analysis` |
| الفلاتر | `GET /filters` |
| الإعدادات | `GET /settings` |

| القدرة | المكان |
| --- | --- |
| بدء الالتقاط وإيقافه | `POST /api/start` و`POST /api/stop` |
| حالة التسجيل | `GET /api/status` |
| صفحات حزم | `GET /api/packets` |
| حزمة واحدة | `GET /api/packets/<id>` |
| إحصاءات | `GET /api/stats` |
| توزيع بروتوكولات | `GET /api/protocols` ونسب `GET /api/protocol-percentages` |
| أعلى عناوين | `GET /api/top-ips` |
| أعلى منافذ | `GET /api/analysis/ports` |
| الزمن | `GET /api/analysis/time` |
| مؤشرات شذوذ | `GET /api/analysis/anomalies` |
| واجهات الشبكة | `GET /api/interfaces` |
| مسح الحزم | `POST /api/clear` |
| حفظ فلتر واستعلامها | `POST /api/filters/save` و`GET /api/filters` |
| تصدير CSV | `GET /api/export/csv` |
| إعدادات | `GET/POST /api/settings` |
| حدث فوري | `new_packet` و`stats_update` و`status` |

التصنيف في `analyzer.py`: ARP وICMP وDNS وHTTP (منافذ 80 و443 و8080 على TCP) وTCP وUDP وOther. النص المخزن للحمولة يُقص إلى 8000 حرفاً.

الحد الافتراضي لعدد الحزم في الإعداد: `max_packets` يساوي 100000، مع قص الصفوف الزائدة في `database.py`.

## 4 أمثلة واقعية

حزمة مخزنة أعمدتها: وقت، عنوان مصدر، عنوان وجهة، منفذ مصدر، منفذ وجهة، بروتوكول، حجم، TTL، حمولة، ملخص Scapy.

مؤشر الشذوذ في `anomaly_metrics` يقارن عدد الحزم في آخر 5 دقائق بالخمس دقائق السابقة. يرتفع `spike_detected` إذا كان العدد الحالي أكبر من ثلاثة أضعاف السابق وكان السابق أكبر من صفر، أو إذا كان السابق صفراً والحالي أكبر من 100.

منافذ تُراقَب في الاستعلام الدفاعي للعدّ فقط: 4444 و31337 و12345 و6667 و5900 و3389 و22 و23 و135 و445. الناتج عدد الصفوف لكل منفذ وجهة ضمن هذه القائمة. لا يوجد في الدالة إجراء قطع أو تعديل للحزم.

جلسة الالتقاط صف في `sessions` بحالة افتراضية `active` ووقت بداية ونهاية وعدد.

فلتر محفوظ: اسم ونص `filter_json`.

## 5 رحلة الاستخدام

1. تثبيت Python وNpcap كما في الدليل السابق، ثم `pip install -r requirements.txt`.
2. `python app.py` يستدعي `init_db` و`sniffer.init_sniffer` ويطبع `http://127.0.0.1:5000`.
3. الصفحة الرئيسية تعرض الحالة.
4. بدء الالتقاط من `/api/start` مع واجهة اختيارية.
5. كل حزمة تمر بـ `classify_and_extract` ثم `insert_packet`.
6. Socket.IO يبث `new_packet` وحلقة الإحصاء تبث `stats_update`.
7. الإيقاف عبر `/api/stop`. عند Ctrl+C تُستدعى `prepare_for_exit` ثم `shutdown_wal`.

`async_mode` لـ SocketIO هو `threading`. التعليق في أعلى `app.py` يذكر أن eventlet غير مستخدم حتى يبقى Windows مستجيباً مع SQLite.

## 6 الوحدات البرمجية

| الملف | الدور |
| --- | --- |
| `app.py` | الصفحات وREST وSocket.IO والإصدار |
| `sniffer.py` | AsyncSniffer والبدء والإيقاف وبث الأحداث وعداد الحزم في الثانية |
| `analyzer.py` | استخراج الحقول وتصنيف البروتوكول |
| `database.py` | SQLite والقفل والإعدادات والاستعلامات والقص |
| `templates/` | HTML |
| `static/js/main.js` و`static/css/style.css` | الواجهة |
| `local_settings.json` | واجهة الشبكة و`max_packets` |
| `assets/` | ملفات تُخدم من `/assets/<path>` |

## 7 الكيانات

المخطط قُرئ من `sqlite_master` في `packet_analyzer.db` ويطابق `CREATE TABLE` في `database.py`. لم يُنسخ أي صف بيانات.

| الجدول | الأعمدة |
| --- | --- |
| `packets` | `id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `size`, `ttl`, `payload`, `raw_summary` |
| `sessions` | `id`, `start_time`, `end_time`, `total_packets`, `status` |
| `saved_filters` | `id`, `name`, `filter_json`, `created_at` |

فهارس: `idx_packets_timestamp` و`idx_packets_src_ip` و`idx_packets_protocol`.

## 8 الصلاحيات

لا مستخدمون داخل التطبيق. الحماية العملية هي الاستماع على `127.0.0.1` وصلاحية نظام التشغيل للالتقاط.

`SocketIO` مضبوط بـ `cors_allowed_origins="*"`.

## 9 الأتمتة

| السلوك | التفصيل |
| --- | --- |
| خيط الالتقاط | Sniffer في الخلفية |
| حلقة إحصاء | `_stats_loop_forever` تبث `stats_update` |
| قص الجدول | `_trim_packets_locked` عند تجاوز `max_packets` |
| ذاكرة تخزين للاستعلامات الثقيلة | مهلة 3 ثوانٍ في `_QUERY_CACHE_TTL_S` |
| قفل | `threading.RLock` حول الاتصال |
| WAL | دوال pragma وإغلاق في `shutdown_wal` |

لا cron.

## 10 التكامل

Scapy للالتقاط. Npcap على Windows كما وثّق الدليل السابق. Chart.js مذكور في الدليل السابق كرسوم الصفحة. المتصفح يتحدث HTTP وSocket.IO مع نفس الخادم.

## 11 المصطلحات

| المصطلح | المعنى في المشروع |
| --- | --- |
| حزمة | صف في `packets` بعد استخراج الملخص |
| PPS | عدد الحزم في النافذة الحالية من `current_pps` |
| TTL | عمود `ttl` |
| BPF | مذكور في الدليل السابق كمفهوم عام. الفلترة في التطبيق عبر معاملات الاستعلام و`saved_filters` |
| WAL | نمط دفتر SQLite الذي يُغلق عند الخروج |
| الإصدار | `1.0.0` |

الدليل السابق شرح eventlet ضمن المسرد. الكود الحالي يضبط `async_mode="threading"` ويذكر في التعليق تجنب eventlet.

## 12 الأسئلة الشائعة

| السؤال | الجواب |
| --- | --- |
| هل يفتح من الإنترنت؟ | المضيف `127.0.0.1` |
| ما المنفذ؟ | 5000 |
| أين الملف؟ | `packet_analyzer.db` |
| ما الحد؟ | 100000 حزمة ما لم تُغيَّر `max_packets` |
| هل يلزم Npcap؟ | الدليل السابق يربطه بالتقاط Windows. الكود يكتم تحذير libpcap ولا يثبت Npcap بنفسه |
| ما إصدار بايثون في الدليل السابق؟ | 3.10.6. لا `runtime.txt` في المجلد |
| هل تُمسح الحزم؟ | `POST /api/clear` يستدعي `clear_all_packets` |

## 13 البنية المعمارية

```
بطاقة الشبكة
    |
    v
Scapy AsyncSniffer  (sniffer.py)
    |
    v
analyzer.classify_and_extract
    |
    v
SQLite packet_analyzer.db
    ^
    |
Flask 127.0.0.1:5000
    |-- صفحات HTML
    |-- /api/*
    |-- Socket.IO: new_packet, stats_update, status
    |
    v
المتصفح (Chart.js حسب الدليل السابق)
```

## 14 التقنيات

| الحزمة | الإصدار في `requirements.txt` |
| --- | --- |
| flask | 2.3.3 |
| flask-socketio | 5.3.6 |
| scapy | 2.5.0 |
| python-socketio | 5.9.0 |

SQLite من المكتبة القياسية. الإصدار التطبيقي `1.0.0` منفصل عن إصدارات الحزم.

الدليل السابق يذكر Python 3.10.6 وNpcap 1.79 كروابط تثبيت. هذان الرقمان غير مثبتين داخل `requirements.txt`.

## 15 شجرة الملفات

```
Packet Analyzer/
├── app.py
├── sniffer.py
├── analyzer.py
├── database.py
├── requirements.txt
├── README.md
├── local_settings.json
├── packet_analyzer.db
├── assets/
├── static/css/style.css
├── static/js/main.js
└── templates/
    ├── base.html
    ├── index.html
    ├── packets.html
    ├── analysis.html
    ├── filters.html
    └── settings.html
```

قد تظهر ملفات دفتر SQLite الجانبية (`-wal` أو `-shm`) أثناء التشغيل. `shutdown_wal` تُستدعى عند الإيقاف.

## 16 الواجهة الأمامية

قوالب Jinja تأخذ `version`. الشكل في `static/css/style.css` والسلوك في `static/js/main.js`. لا React أو Vue حسب الدليل السابق، وهذا يطابق غياب تلك الحزم من `requirements.txt`.

الأصول من المسار `/assets/<filename>`.

## 17 الخادم الخلفي

Flask مع SocketIO بنمط threading. `SECRET_KEY` يُولَّد بـ `os.urandom(24).hex()` عند كل إقلاع. `debug=False` و`use_reloader=False` في `socketio.run`.

`allow_unsafe_werkzeug=True` ممرَّر إلى `socketio.run`.

## 18 تدفق الطلب

```
POST /api/start
  -> واجهة اختيارية
  -> start_capture
  -> AsyncSniffer
  -> _packet_callback
  -> classify_and_extract
  -> insert_packet
  -> emit new_packet

GET /api/packets
  -> معاملات الصفحة والفلتر
  -> get_packets_page
  -> JSON

GET /api/export/csv
  -> نفس مرشحات الاستعلام
  -> ملف CSV في الاستجابة
```

## 19 قاعدة البيانات

الملف `packet_analyzer.db`. الجداول والفهارس في القسم 7، مطابقة لما أعاده `sqlite_master` دون قراءة صفوف.

إعدادات الاتصال في `database.py` تطبّق pragma عبر `_apply_pragmas`. قص الصفوف يحذف الأقدم عند تجاوز `max_packets`.

`local_settings.json` مفاتيحه الافتراضية: `interface` سلسلة فارغة و`max_packets` العدد 100000.

## 20 نقاط النهاية

| الطريقة | المسار |
| --- | --- |
| GET | `/` |
| GET | `/packets` |
| GET | `/analysis` |
| GET | `/filters` |
| GET | `/settings` |
| GET | `/assets/<path>` |
| POST | `/api/start` |
| POST | `/api/stop` |
| GET | `/api/status` |
| GET | `/api/packets` |
| GET | `/api/packets/<packet_id>` |
| GET | `/api/stats` |
| GET | `/api/protocols` |
| GET | `/api/top-ips` |
| GET | `/api/settings` |
| POST | `/api/settings` |
| GET | `/api/interfaces` |
| POST | `/api/clear` |
| POST | `/api/filters/save` |
| GET | `/api/filters` |
| GET | `/api/export/csv` |
| GET | `/api/analysis/ports` |
| GET | `/api/analysis/time` |
| GET | `/api/analysis/anomalies` |
| GET | `/api/protocol-percentages` |

حدث Socket.IO عند الاتصال يبث `status` فيه `recording`.

## 21 المصادقة

غير موجود في الملفات الحالية. مفتاح الجلسة عشوائي لكل عملية.

## 22 الأمان

السلوك الموجود:

- الاستماع على الحلقة المحلية `127.0.0.1`.
- الالتقاط على واجهة يختارها المشغّل على جهازه.
- قص حجم الحمولة المخزنة إلى 8000 حرفاً.
- قص عدد الصفوف إلى `max_packets`.
- استعلامات القراءة بمعاملات، ومنها صفحات الحزم.
- مؤشر الشذوذ للعرض فقط: ارتفاع مفاجئ في العدد، وعدّ منافذ وجهة من قائمة ثابتة.
- إغلاق منظم لخيط الالتقاط وWAL عند Ctrl+C.
- `debug=False`.

ظواهر حالية:

- لا تسجيل دخول، فأي برنامج على نفس الجهاز يصل إلى المنفذ 5000 يستطيع طلب المسح أو البدء.
- CORS لمقبس Socket.IO بالقيمة `*`.
- `POST /api/clear` يحذف الحزم المخزنة.
- الدليل السابق طلب تشغيل الطرفية كمسؤول على Windows للالتقاط. هذا متطلب نظام وليس حساباً داخل التطبيق.

## 23 الإعدادات

| البند | القيمة |
| --- | --- |
| الإصدار | 1.0.0 |
| المضيف | 127.0.0.1 |
| المنفذ | 5000 |
| async_mode | threading |
| ping_timeout | 60 |
| ping_interval | 25 |
| max_packets الافتراضي | 100000 |
| interface الافتراضي | فارغ |
| مهلة كاش الاستعلام | 3 ثوانٍ |
| مفتاح Flask | عشوائي عند الإقلاع |

## 24 التكاملات الخارجية

Scapy وNpcap على Windows. لا خدمة سحابية في `app.py`.

## 25 المهام والجدولة

خيط التقاط وخيط إحصاء طوال تشغيل الخادم. لا جدولة زمنية خارجية.

## 26 الملفات المهمة

`packet_analyzer.db` قد يكبر حتى حد `max_packets` وحجم الحمولة. لا تنسخ محتواه إلى دليل عام. `local_settings.json` إعداد الواجهة والحد. ملفات WAL مؤقتة أثناء الكتابة.

## 27 السجلات

طباعة بدء التشغيل والإيقاف في الطرفية. ملف log تطبيقي: غير موجود في الملفات الحالية. أخطاء بعض المسارات ترجع JSON فيه `error`.

## 28 التثبيت

```
cd "D:\VSCode\Projects\Packet Analyzer"
pip install -r requirements.txt
python app.py
```

على Windows ثبّت Npcap مع وضع توافق WinPcap كما شرح الدليل السابق، ثم أعد فتح الطرفية. شغّل العملية بصلاحية تسمح بالالتقاط إذا رفضت الواجهة البدء.

افتح `http://127.0.0.1:5000`.

## 29 دليل التطوير

- تصنيف بروتوكول جديد: عدّل `classify_and_extract` ثم تأكد أن الواجهة تعرف الاسم.
- عمود جديد: أضفه في `init_db` وعلى قاعدة موجودة بتهجير صريح. `CREATE TABLE IF NOT EXISTS` لا يغيّر جدولاً قديماً.
- أبقِ الاستعلامات الثقيلة خلف `_db_lock`.
- تجنب eventlet على Windows حسب تعليق `app.py`.

## 30 النشر

الاستماع مثبت على `127.0.0.1`. ملفات منصة سحابية: غير موجود في الملفات الحالية. النشر العام يعارض قيد المضيف الحالي.

## 31 النسخ الاحتياطي

أوقف الخادم حتى يُغلق WAL، ثم انسخ `packet_analyzer.db` و`local_settings.json`. لا سكربت نسخ في الملفات الحالية. الملف قد يكون كبيراً. لا تُدرج صفوف الحزم في المستندات.

## 32 استكشاف الأخطاء

| العرض | المصدر |
| --- | --- |
| No libpcap provider | Npcap غير متاح. التحذير مكبوت في الكود وقد يبقى الالتقاط متعذراً |
| الالتقاط لا يبدأ | صلاحية المسؤول أو اسم الواجهة |
| الصفحة لا تُفتح من جهاز آخر | المضيف 127.0.0.1 |
| القاعدة تتضخم | ارفع القص عبر `max_packets` أو امسح عبر `/api/clear` |
| Ctrl+C بطيء | التعليق يذكر أن threading و`shutdown_wal` لمعالجة هذا على Windows |
| المنفذ مشغول | 5000 ثابت |

## 33 الاعتماديات

Flask 2.3.3 وflask-socketio 5.3.6 وscapy 2.5.0 وpython-socketio 5.9.0. Npcap حزمة نظام خارج pip.

## 34 القيود

- محلي على الواجهة المختارة.
- التصنيف تقريبي: TCP على منافذ 80 و443 و8080 يُعلَّم HTTP حتى لو كان المحتوى غير ذلك.
- مؤشر الشذوذ عددي للعرض.
- CORS المقبس مفتوح بينما HTTP على الحلقة المحلية.
- eventlet مذكور في الدليل السابق وغير مستخدم في `socketio.run`.
- Python 3.10.6 وNpcap 1.79 من الدليل السابق وليسا قيدَ إصدار داخل المستودع.

## 35 الحالة الحالية

تطبيق بالإصدار 1.0.0 مع خمس صفحات وواجهات REST وقاعدة فيها الجداول الثلاثة والفهارس الثلاثة. ملف الإعدادات المحلية موجود.

## 36 القرارات

| القرار | السبب المكتوب |
| --- | --- |
| threading بدل eventlet | تعليق توافق Windows مع SQLite وCtrl+C |
| المضيف 127.0.0.1 | البقاء على الجهاز |
| حد 100000 | ضبط حجم الملف |
| كاش 3 ثوانٍ | تعليق أن GROUP BY على جداول كبيرة يمسك القفل |
| مفتاح عشوائي كل إقلاع | `os.urandom` |

تناقض المسرد السابق: وجود eventlet كمكتبة تشغيل. الكود يختار threading.

## 37 الاختبار

اختبارات pytest: غير موجود في الملفات الحالية. التحقق التشغيلي من `/api/status` ومن صفحة الحزم بعد بدء الالتقاط.

## 38 متطلبات التشغيل

بايثون مع pip. الدليل السابق يوصي بـ 3.10.6. Npcap على Windows للالتقاط الحقيقي. صلاحية تلتقط من الواجهة. متصفح على نفس الجهاز. مساحة للملف `packet_analyzer.db`.

## 39 سجل التغييرات

الإصدار الحالي في `app.py`: `1.0.0` ويُمرَّر إلى القوالب وإلى `/api/status` و`/api/settings`. سجل فروقات بين إصدارات: غير موجود في الملفات الحالية.

## System Overview

ملتقط حزم محلي، تصنيف بروتوكول، تخزين SQLite بحد أقصى، واجهة عربية، وتحديث Socket.IO. التحليل يعرض توزيعات وارتفاعاً مفاجئاً في العدد ومنافذ وجهة من قائمة مراقبة.

## Quick Reference

| البند | القيمة |
| --- | --- |
| التشغيل | `python app.py` |
| العنوان | `http://127.0.0.1:5000` |
| الإصدار | 1.0.0 |
| القاعدة | `packet_analyzer.db` |
| حد الحزم | 100000 |
| النمط | threading |

## Quick Start

```
cd "D:\VSCode\Projects\Packet Analyzer"
pip install -r requirements.txt
python app.py
```

ثبّت Npcap على Windows قبل الالتقاط. افتح `http://127.0.0.1:5000` ثم ابدأ التسجيل من الواجهة.

## For Non-Technical Users

التطبيق يراقب حركة جهازك فقط ويعرض من يتصل وبأي بروتوكول وبأي حجم. الرسومات تتحدث أثناء التسجيل. يمكنك إيقاف التسجيل أو مسح الجدول أو تنزيل CSV. مؤشر التحليل يخبرك إن زاد عدد الحزم فجأة مقارنة بالدقائق السابقة.

## For Developers

ابدأ من `start_capture` ثم `_packet_callback` ثم `insert_packet`. أبقِ القفل حول الكتابة. لا تطبع حمولة الحزم في السجلات. عند تغيير المخطط أضف تهجيرًا لأن الجداول الحالية أُنشئت بـ `IF NOT EXISTS` وتطابق الأعمدة المذكورة في القسم 7.
