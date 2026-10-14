# ☕ កាហ្វេ ម្លប់ដូង — Backend + Admin API

Node.js + Express + SQLite (ឯកសារតែមួយ `data/mlob-doung.db` មិនបាច់ដំឡើង Database Server)

**តម្រូវការ:** Node.js **v22.13 ឡើងទៅ** (ពិនិត្យដោយ `node -v`)។ ប្រើ SQLite ដែលមានស្រាប់ក្នុង Node ដូច្នេះ `npm install` មិនត្រូវការ Visual Studio / compile អ្វីទាំងអស់។

## ចាប់ផ្តើម
```bash
npm install
cp .env    # កែ ADMIN_PASSWORD ជាមុនសិន!
npm start                # http://localhost:3000
```
បើក http://localhost:3000 — Front-end (`public/index.html`) ត្រូវបានបម្រើដោយ Server តែមួយ ដូច្នេះមិនបាច់កំណត់ API URL ទេ។

បើមិនបានបង្កើត `.env` គណនីដំបូងគឺ `admin / 123456` (Server នឹងព្រមាន) — **សូមប្តូរភ្លាមៗ** តាមប៊ូតុង «ប្តូរពាក្យសម្ងាត់» ក្នុង Admin។ គណនីនេះត្រូវបានបង្កើតតែម្តង ពេល database នៅទទេ ដូច្នេះការកែ `.env` ក្រោយមកមិនប្តូរពាក្យសម្ងាត់ដែលមានស្រាប់ទេ។

## API

**Public (POS / KDS)**

| Method | Path | ការងារ |
|---|---|---|
| GET | `/api/products` | ទំនិញ active សម្រាប់ POS |
| POST | `/api/orders` | បង្កើតការកម្ម៉ង់ `{customerName, tableNo, items:[{id, quantity, sugar}]}` — Server គណនាតម្លៃ/សរុប និងកាត់ស្តុកដោយខ្លួនឯង |
| GET | `/api/orders[?status=]` | បញ្ជីការកម្ម៉ង់ (៧ ថ្ងៃចុងក្រោយ) |
| PATCH | `/api/orders/:id/status` | `pending → preparing → completed / cancelled` (បោះបង់ = ស្តុកត្រឡប់មកវិញ) |

**Auth**

| Method | Path | ការងារ |
|---|---|---|
| POST | `/api/auth/login` | `{username, password}` → `{token}` (JWT 8 ម៉ោង, កំណត់ ២០ ដង/១៥ នាទី) |
| GET | `/api/auth/me` | ពិនិត្យ token |
| POST | `/api/auth/change-password` | `{currentPassword, newPassword}` |

**Admin** (ត្រូវការ `Authorization: Bearer <token>`)

| Method | Path | ការងារ |
|---|---|---|
| GET / POST | `/api/admin/products` | បញ្ជីទាំងអស់ / បន្ថែម |
| PUT / PATCH / DELETE | `/api/admin/products/:id` | កែទាំងមូល / កែខ្លះ (status…) / លុប |
| POST | `/api/admin/products/:id/stock` | `{delta: +5}` កែស្តុកបែប atomic |
| POST | `/api/admin/upload` | form-data `image` (JPG/PNG/WEBP/GIF ≤ 5MB) → `{url}` |
| GET | `/api/admin/stats` · `/api/admin/orders` | ស្ថិតិ · ប្រវត្តិការកម្ម៉ង់ |

## Deploy
- Server តែមួយ (VPS, Render, Railway…): រត់ `npm start` ហើយរក្សា folder `data/` និង `uploads/` ឱ្យនៅ (persistent disk)។
- ដាក់ HTTPS នៅពីមុខ (Nginx / Caddy / Cloudflare) មុនប្រើជាក់ស្តែង — JWT ធ្វើដំណើរក្នុង Header។
- បើ Front-end នៅ host ផ្សេង: កំណត់ `CORS_ORIGIN` នៅ Server ហើយបញ្ចូល API URL ក្នុង «ការកំណត់ Backend API» នៅ Admin។

## កំណត់សម្គាល់សុវត្ថិភាព
- **KDS (`/api/orders`) បើកសាធារណៈ** ដូចរចនាសម្ព័ន្ធដើម (ទំព័រ Orders មិនមាន login)។ អ្នកដឹង URL អាចមើល/ប្តូរស្ថានភាពការកម្ម៉ង់បាន។ បើចង់បិទ សូមដាក់ `requireAdmin` ឬបង្កើត login បុគ្គលិក។
- ឈ្មោះអតិថិជន/ទំនិញត្រូវបាន escape ក្នុង Front-end ដើម្បីការពារ XSS។
