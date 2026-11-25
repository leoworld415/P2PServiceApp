# Node R 盲目中繼（強化版）

這是 P2PServiceApp SSD v2.1 裏 Node R 的可運行實作：店內電腦作為盲目中繼，只保存已加密的上行信封，不以明文處理服務紀錄。本目錄是獨立程式，方便先在本機驗證，並未改動倉庫根目錄的 `README.md` 或 `docs/SSD_v2.1.md`。

## 你會得到什麼

- `node_r.py`：FastAPI 服務與管理指令（登記／撤銷裝置、啟動伺服器）
- `client_demo.py`：示範如何用 Ed25519 簽署請求，並走完上傳 → 提取 → 確認 → 查狀態
- `test_node_r.py`：pytest 單元測試（以 FastAPI TestClient 執行）
- 預設只綁定 `127.0.0.1`；可用環境變數或參數改主機、TLS 與網段允許清單

## 安裝

需要 Python 3.10 或以上。

```bash
cd node-r
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 啟動

```bash
python node_r.py serve
# 等同：綁定 127.0.0.1:8000，資料庫為 ./node_r.db
```

健康檢查（無需認證，回傳伺服器 Unix 時間，供客戶端校正時鐘）：

```bash
curl http://127.0.0.1:8000/api/v2/health
```

常用參數與環境變數：

| 項目 | 環境變數 | 預設 |
| --- | --- | --- |
| 資料庫路徑 | `NODE_R_DB` | `node_r.db` |
| 綁定位址 | `NODE_R_HOST` | `127.0.0.1` |
| 連接埠 | `NODE_R_PORT` | `8000` |
| 時間窗（秒） | `NODE_R_CLOCK_SKEW` | `300` |
| 解碼後信封上限 | `NODE_R_MAX_ENVELOPE` | `65536`（64 KB） |
| 每部裝置待處理上限 | `NODE_R_PENDING_CAP` | `5000` |
| 磁碟剩餘下限 | `NODE_R_DISK_MIN_FREE` | `209715200`（200 MB，不足則回 507） |
| 請求本文上限 | `NODE_R_MAX_BODY` | `131072`（128 KB） |
| 允許的 CIDR（逗號分隔） | `NODE_R_ALLOWED_CIDRS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7` |
| 是否強制 CIDR | `NODE_R_ENFORCE_CIDR` | `1` |
| TLS 憑證／金鑰 | `NODE_R_SSL_CERT`、`NODE_R_SSL_KEY` | 未設定 |

綁定區網位址（仍建議加上防火牆與 TLS）：

```bash
python node_r.py serve --host 192.168.1.10 --port 8000
```

中介軟體只信賴 `request.client.host`，不會讀取 `X-Forwarded-For`，以免來源位址被偽冒。

## 登記與撤銷裝置

先在技師或老闆的裝置產生 Ed25519 金鑰對，只把**公鑰**交給店內中繼。可用 PyNaCl，或跑一次 `client_demo.py` 觀察流程（示範私鑰預設只留在記憶體）。

```bash
python node_r.py register \
  --device-id therapist-1 \
  --role THERAPIST \
  --pubkey '<64 字元公鑰 hex>' \
  --db node_r.db

python node_r.py register \
  --device-id boss-1 \
  --role BOSS \
  --pubkey '<64 字元公鑰 hex>' \
  --db node_r.db

python node_r.py revoke --device-id therapist-1 --db node_r.db
```

未在白名單的裝置會得到 401；狀態不是 `ACTIVE` 的裝置會得到 403。沒有「查不到就放行」的測試後門。

`register` 若遇到已存在的 `device_id`，會更新角色與公鑰，並把狀態設回 `ACTIVE`（適合金鑰輪替）。請用同一個 `--db`（或 `NODE_R_DB`）對應正在運行的伺服器。

## 簽署格式

客戶端以裝置私鑰簽署以下 UTF-8 字串（五段以換行連接）：

```
METHOD
PATH
TIMESTAMP
NONCE
SHA256_HEX(raw body bytes)
```

- `METHOD`：大寫，例如 `POST`
- `PATH`：只含路徑，**不含** query string。例如查狀態時路徑是 `/api/v2/uplink/status`
- `TIMESTAMP`：Unix 秒的十進位字串，須落在伺服器時間加減 `CLOCK_SKEW` 秒之內
- `NONCE`：同一裝置在時間窗內不可重複
- `SHA256_HEX`：原始請求本文的小寫十六進位 SHA-256。空本文（GET 常見）是對空位元組雜湊，即 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

把簽章以十六進位放在 `X-Signature`，並同時送出 `X-Device-Id`、`X-Timestamp`、`X-Nonce`。伺服器以 `await request.body()` 取得原始位元組計算雜湊，因此客戶端必須簽署**實際送出的位元組**，不要對「解析後再序列化」的 JSON 簽署。

時鐘校正：先呼叫 `GET /api/v2/health` 取得 `server_unix_ts`，用 `offset = server_unix_ts - local_unix_ts`，再以 `local + offset` 作為簽署時間。

共用函式見 `node_r.sign_request` 與 `client_demo.signed_headers`。

## 角色與 API

| 方法 | 路徑 | 角色 | 說明 |
| --- | --- | --- | --- |
| GET | `/api/v2/health` | 無需認證 | 心跳與伺服器時間 |
| POST | `/api/v2/uplink/records` | THERAPIST | 上傳 Base64 信封。同一裝置、同一 `client_record_id`、同一信封會回傳既有 `relay_id`；信封不同則 409。上限 64 KB（解碼後），每部裝置待處理筆數有上限。 |
| GET | `/api/v2/uplink/status?client_record_id=` | THERAPIST | 只查自己裝置的紀錄，狀態為 `queued`、`acked` 或 `unknown` |
| GET | `/api/v2/uplink/fetch?limit=` | BOSS | 由舊到新提取，最多 200 筆，信封以 Base64 回傳，含 `device_id` |
| POST | `/api/v2/uplink/ack` | BOSS | 簽署收據並清除已入帳的 `relay_ids` |
| DELETE | `/api/v2/uplink/purge` | BOSS | ack 的別名，同樣需要已簽署的 JSON 本文 |

### 確認（ack）流程

1. 老闆端提取密文，**先寫入本地總帳並確認成功**。
2. 才呼叫 `POST /api/v2/uplink/ack`，本文為 `{"relay_ids":[...]}`。此請求已由老闆簽章，簽署過的本文就是收據。
3. Node R 先把收據寫入 `ack_log`（含老闆裝置、relay_ids、body SHA-256、簽章、時間），再刪除佇列中確實存在的列，並回傳 `purged_ids`。
4. 技師端以 `/api/v2/uplink/status` 查詢；在狀態變成 `acked` 之前，不要把該筆標為已送達。這樣中繼機在老闆入帳前損壞時，技師手機仍保留原稿。

## 跑測試與示範

```bash
source venv/bin/activate
pytest -q test_node_r.py
```

對正在運行的伺服器做端到端示範（示範腳本會把示範裝置寫入**同一個**資料庫，請指向伺服器在用的路徑）：

```bash
# 終端機 A
NODE_R_DB=/tmp/node_r_demo.db python node_r.py serve --host 127.0.0.1 --port 8000

# 終端機 B
python client_demo.py --base-url http://127.0.0.1:8000 --db /tmp/node_r_demo.db
```

不要把 `*.db`、私鑰、自簽憑證提交到 Git。`.gitignore` 已排除這些檔案。

## 以自簽憑證啟用 TLS

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout node_r_key.pem -out node_r_cert.pem \
  -days 365 -nodes -subj "/CN=node-r.local"

python node_r.py serve \
  --host 127.0.0.1 --port 8443 \
  --ssl-cert node_r_cert.pem \
  --ssl-key node_r_key.pem
```

客戶端必須信任該憑證（或在測試時明確指定 CA）。正式環境應改用由內網 CA 或 ACME 簽發的證書，不要把私鑰放進版本庫。

## systemd 單元示例

把專案放在 `/opt/p2pservice/node-r`，以專用系統使用者運行，並先完成 `venv` 安裝。將下列內容存成 `/etc/systemd/system/node-r.service`：

```ini
[Unit]
Description=Node R blind relay
After=network.target

[Service]
Type=simple
User=node-r
Group=node-r
WorkingDirectory=/opt/p2pservice/node-r
Environment=NODE_R_DB=/var/lib/node-r/node_r.db
Environment=NODE_R_HOST=127.0.0.1
Environment=NODE_R_PORT=8000
# Environment=NODE_R_SSL_CERT=/etc/node-r/cert.pem
# Environment=NODE_R_SSL_KEY=/etc/node-r/key.pem
ExecStart=/opt/p2pservice/node-r/venv/bin/python node_r.py serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

然後執行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now node-r.service
```

若要讓區網裝置連線，可把 `NODE_R_HOST` 改成該機的區網 IP，並用防火牆只放行店內網段。更穩妥的做法是綁定本機，再由反向代理提供 TLS。

## 正式上線前仍須補上的項目

這個版本修補了原 PoC 的認證、角色、重放、冪等與過早清除等問題，但仍不是完整的生產系統：

- 以 LUKS（或其他全碟加密）保護中繼機硬碟；本機 SQLite 目前**沒有**庫級加密
- 自動異地備份，並演練復原（稅務與營運紀錄的保存期需符合當地法規）
- 資料庫權限、系統使用者與檔案權限收緊；考慮 SQLCipher 或等價方案
- 以店內網段防火牆限制來源；TLS 要用可信憑證，不要依賴明文 HTTP
- 管理員指令（`register`／`revoke`）應只在主控台或受保護管道執行
- 仍不能防止「根本不開單」的漏單；對數基準應來自前台開單或排班
- 裝置遺失與更換的復原流程（本服務把公鑰綁在 `device_id` 上）
- 日誌已避免寫出完整信封與簽章；部署時仍須檢查輪替與存取權

## 授權與範圍

本目錄只用於該計劃的本機實作與測試，請勿把真實客人資料放到未加密的開發庫。
