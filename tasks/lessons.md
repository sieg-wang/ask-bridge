# Lessons Learned

## 2026-07-10 Windows Chrome ownership 與登入判斷回歸

- Mistake class: incorrect assumption about repository/runtime behavior、missing verification。
- Failure mode: 把 `Command::spawn()` 回傳的 Chrome launcher PID 當成最終 9223 listener，並假設 WMI/CIM parent-chain 永遠可查；同時以單次 ChatGPT DOM snapshot 決定登入狀態。
- Detection signal: verbose log 同時出現不同的 `recorded PID`／`listener PID`、空的 `ask-bridge owner PIDs`，登入完成後為 `Unknown`，下一次 query 又立即成為 `LoggedOut`。
- Prevention rule: Windows Chrome 啟動完成後必須驗證 listener 來源、記錄實際 listener 與 CDP browser identity；reuse／close 共用同一 ownership snapshot，強殺前重新驗證。登入 UI 必須經 bounded stabilization，未穩定只能回 `Unknown`，不得硬判登出。
- Tripwires:
  - 單元測試固定涵蓋 launcher PID 與 listener PID 不同、WMI 空白列、9223／92230 精確解析、stale identity、mixed listeners 與強殺 identity 改變。
  - 單元測試固定涵蓋 ChatGPT auth path precedence、composer-only provider 差異、未穩定訊號不得成為 `LoggedIn`／`LoggedOut`。
  - Windows release 前執行 login → 保持 Chrome 開啟 → query → graceful close → restart query 的真機流程；若無法執行，必須明確記錄限制，不得只以跨平台單元測試宣稱 session 問題已解決。
