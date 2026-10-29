/**
 * @file SecurityMonitorPage.jsx
 * @description [관리자 전용] SOC 실시간 패킷 모니터링 페이지입니다.
 * C언어(libpcap) 엔진이 캡처한 트래픽 로그를 대시보드 형태로 보여줍니다.
 */

import React, { useState } from 'react';
import './SecurityMonitorPage.css';

const SecurityMonitorPage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: 1초 단위로 '/api/security/logs'를 폴링(Polling)하거나 WebSocket으로 실시간 수신합니다.
  const [logs, setLogs] = useState([
    { id: 1, time: '12:05:28', src: '45.33.2.11', dest: '192.168.1.5', protocol: 'TCP', info: 'SYN Flooding 의심' },
    { id: 2, time: '12:05:25', src: '192.168.1.10', dest: '8.8.8.8', protocol: 'UDP', info: 'DNS Query (google.com)' }
  ]);

  return (
    <div className="soc-monitor-container" style={{ backgroundColor: '#0f172a', color: '#e2e8f0', padding: '20px', minHeight: '100%', borderRadius: '10px' }}>
      <h3 style={{ color: '#38bdf8', borderBottom: '1px solid #1e293b', paddingBottom: '15px' }}>
        🛡️ 실시간 네트워크 패킷 감시 (SOC)
      </h3>

      <div style={{ marginTop: '20px', backgroundColor: '#1e293b', padding: '15px', borderRadius: '8px' }}>
        <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ color: '#94a3b8', borderBottom: '1px solid #334155' }}>
              <th style={{ padding: '10px' }}>Time</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Protocol</th>
              <th>Info / Payload</th>
            </tr>
          </thead>
          <tbody>
            {logs.map(log => (
              <tr key={log.id} style={{ borderBottom: '1px solid #273548' }}>
                <td style={{ padding: '10px', color: '#10b981' }}>{log.time}</td>
                <td style={{ color: '#f87171' }}>{log.src}</td>
                <td style={{ color: '#60a5fa' }}>{log.dest}</td>
                <td style={{ color: '#fbbf24' }}>{log.protocol}</td>
                <td>{log.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SecurityMonitorPage;
