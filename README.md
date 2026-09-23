# THM-Unified-Kill-Chain
מדריך מקיף ושלם המתעד את תהליך החקירה ב-Kibana SIEM ומיפוי שלבי התקיפה לפי מסגרת העבודה Unified Kill Chain (UKC). המדריך מותאם לפרסום ישיר ב-GitHub כקובץ README.md.


# TryHackMe: Unified Kill Chain & Threat Investigation — Full Walkthrough & Guide



<img width="1905" height="511" alt="image" src="https://github.com/user-attachments/assets/2e2127ee-f72c-4c72-9604-50e4c190156a" />


מדריך מקיף ושלם המתעד את תהליך החקירה ב-Kibana SIEM ומיפוי שלבי התקיפה לפי מסגרת העבודה **Unified Kill Chain (UKC)**. המדריך מותאם לפרסום ישיר ב-GitHub כקובץ `README.md`.

---

## 1. מבוא (Introduction & Context)

מסגרת ה-**Unified Kill Chain (UKC)** מרחיבה את מודל ה-Cyber Kill Chain הקלאסי של Lockheed Martin ומאחדת אותו יחד עם עקרונות מ-MITRE ATT&CK. מטרת המודל היא לספק תמונה הוליסטית של כלל שלבי התקיפה — החל מאיסוף המידע המקדים, דרך ביסוס האחיזה ברשת הפנימית, ועד למימוש היעדים הסופיים של התוקף.

במעבדה זו בוצע שילוב של שני היבטים מרכזיים בעבודת אנליסט SOC / חוקר איומים:

1. **SIEM Threat Hunting (Kibana & KQL):** חקירת לוגים של חיבורי VPN חשודים, סינון לפי פרמטרים מרובים ואיתור אנומליות.
2. **Threat Framework Mapping (UKC Match):** סיווג ותרגום פעולות תוקף לשלבי התקיפה המתאימים במסגרת ה-Unified Kill Chain.

---

## 2. חקירת לוגים ב-SIEM (Kibana / Elastic Discover)

בשלב זה חקרנו לוגים מתוך ה-Data View בשם `vpn_connections` כדי לזהות התנהגות חריגה וחיבורים אסורים.

### Task 5: KQL Log Filtering

#### שאילתה 1: איתור חיבורים מארה"ב עבור משתמשים נבחרים

* **מטרה:** סינון רשומות חיבור שבהן מדינת המקור היא ארצות הברית, והמשתמש שהתחבר הוא James או Albert.
* **טווח זמנים:** הרחבה ל-Last 15 years (או מ-`2021-12-31` עד `2022-02-02`) כדי לכלול את כל הנתונים ההיסטוריים.
* **שאילתת KQL:**
```kql
Source_Country: "United States" and (UserName: "James" or UserName: "Albert")

```


* **ממצאים ותוצאה:**
* התקבלו **161 hits** ברשומות הלוגים.



#### שאילתה 2: חיבורי VPN של עובד שפוטר

* **מטרה:** איתור ניסיונות התחברות של המשתמש Johny Brown שפוטר בתאריך 01/01/2022, לאחר מועד פיטוריו.
* **שאילתת KQL:**
```kql
UserName: "Johny Brown" and @timestamp >= "2022-01-01"

```


* **ממצאים ותוצאה:**
* התקבל **hit 1** בודד:
* **זמן זיהוי:** `Jan 7, 2022 @ 04:28:47.000`
* **אינדיקציה:** שימוש בחשבון לא מורשה לאחר פיטורין (Stale Account Abuse / Unauthorized Access).





---

### Task 6: Visualizations & Anomaly Detection

ניתוח מגמות של ניסיונות כושלים להתחברות ל-VPN במהלך חודש ינואר 2022.

* **מסנן פעולות כושלות:**
```kql
action: "failed"

```


* **ממצאים:**
1. **כמות ניסיונות שגויים כוללת בחודש ינואר:** **`274`** ניסיונות התחברות כושלים (Hits).
2. **משתמש בעל מספר הכישלונות הגבוה ביותר:** בניתוח הערכים המובילים (`Top Values`) תחת השדה `UserName`, המשתמש **`Simon`** נמצא בראש הרשימה, מה שמעיד על ניסיונות Brute Force או בעיית הרשאות חמורה.



---

## 3. מיפוי תקיפה לפי Unified Kill Chain (UKC)

להלן ניתוח הפעולות שנבחנו במסגרת התרחישים המעשיים וסיווגן לשלבי ה-UKC המתאימים:

| תרחיש פעולת התוקף (Scenario Action) | שלב ה-UKC המתאים | הסבר ומשמעות טקטית |
| --- | --- | --- |
| **"The Attacker uses tools to gather information about a system"** | **Reconnaissance** | איסוף מודיעין מקדים (פסיבי או אקטיבי / OSINT) למיפוי משטח התקיפה ותשתיות היעד. |
| **"The Attacker installs a malicious script to allow them remote access at a later date"** | **Persistence** | יצירת מנגנון שרידות והבטחת גישה עתידית לעקיפת אתחולים או ניתוקים של המערכת. |
| **"The hacked machine is being controlled from an Attacker's own server"** | **Command and Control (C2)** | ביסוס ערוץ תקשורת ישיר בין הקורבן לשרת התוקף להזרמת פקודות וקבלת פלט. |
| **"The Attacker uses the hacked machine to access other servers on the same network"** | **Pivoting / Lateral Movement** | שימוש במכונה שנפרצה כמקפצה לרוחב הרשת הפנימית לטובת חדירה לשרתים מוגנים. |
| **"The Attacker steals a database and sells this to a 3rd party"** | **Action and Objectives** | מימוש המטרה הסופית והמניע העסקי/זדוני של המתקפה (אקספילטרציה ופגיעה בארגון). |
<img width="885" height="767" alt="image" src="https://github.com/user-attachments/assets/9eda85b8-e395-480e-9dde-0e055d590e9f" />

* *<img width="943" height="403" alt="image" src="https://github.com/user-attachments/assets/fbe4aede-9edc-4474-ae50-9b9110a0f389" />
*הדגל שהתקבל בסיום הסימולציה:**
```text

![Uploading image.png…]()

THM{UKC_SCENARIO}

```



---

## 4. מושגי מפתח (Key Concepts Summary)

* **Email Harvesting:** איסוף כתובות דוא"ל ממקורות גלויים או מאגרי מידע לטובת קמפיינים ממוקדי פישינג.
* **OSINT Framework:** ממשק מרכז ומובנה המאגד כלים ומקורות גלויים לאיסוף מודיעין על דומיינים, אנשים ורשתות.
* **Malicious Macros:** סקריפטים אוטומטיים (למשל VBA) המוטמעים בקובצי מסמכים (Word/Excel) להרצת פקודות זדוניות בעת פתיחה.
* **Unified Kill Chain (UKC):** מודל בן 18 שלבים המאפשר למגיני סייבר ולצוותי Blue/Red Team לתעד, להבין ולבלום תקיפות מורכבות בכל שכבות מחזור חיי התקיפה.
