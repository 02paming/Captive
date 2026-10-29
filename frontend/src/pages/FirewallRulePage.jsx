/**
 * @file FirewallRulePage.jsx
 * @description [관리자 전용] 방화벽 정책(iptables) 및 접근 제어 관리 페이지입니다.
 * libpcap 엔진과 연동하여 차단(DROP)하거나 허용(ACCEPT)할 IP/Port 규칙을 관리합니다.
 */

import React, { useState } from 'react';
import './FirewallRulePage.css';

const FirewallRulePage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: '/api/admin/firewall/rules' (GET) 호출하여 현재 방화벽 정책을 가져옵니다.
  // (실제로는 백엔드에서 리눅스 iptables -L 명령 결과를 파싱해서 넘겨주거나 DB 테이블에 저장합니다.)
  const [firewallRules, setFirewallRules] = useState([
    { id: 1, type: 'Inbound', src_ip: '45.33.2.11', dest_port: 'ALL', action: 'DROP', reason: 'DDoS 악성 IP 차단 (자동)' },
    { id: 2, type: 'Inbound', src_ip: '192.168.1.0/24', dest_port: '80, 443', action: 'ACCEPT', reason: '사내망 웹 서비스 허용' },
    { id: 3, type: 'Inbound', src_ip: 'ANY', dest_port: '22', action: 'DROP', reason: '외부 SSH 접근 전면 차단' }
  ]);

  return (
    <div className="firewall-container">
      <div className="firewall-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>방화벽 정책 관리 (Firewall Rules)</h3>
          <p>서버에 적용된 iptables 룰셋 및 실시간 접근 제어(ACL) 목록입니다.</p>
        </div>
        <button
          style={{ backgroundColor: '#e74c3c', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer' }}
        >
          + 긴급 차단 IP 등록
        </button>
      </div>

      <table className="board-table">
        <thead>
          <tr>
            <th>Rule ID</th>
            <th>구분 (방향)</th>
            <th>출발지 IP (Source)</th>
            <th>목적지 포트 (Dest)</th>
            <th>정책 (Action)</th>
            <th style={{ width: '30%' }}>적용 사유</th>
          </tr>
        </thead>
        <tbody>
          {firewallRules.map(rule => (
            <tr key={rule.id}>
              <td>{rule.id}</td>
              <td>{rule.type}</td>
              <td style={{ fontWeight: 'bold' }}>{rule.src_ip}</td>
              <td>{rule.dest_port}</td>
              <td>
                <span className={`status-badge ${rule.action === 'ACCEPT' ? 'approved' : 'rejected'}`}>
                  {rule.action}
                </span>
              </td>
              <td style={{ textAlign: 'left', color: '#7f8c8d', fontSize: '13px' }}>{rule.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FirewallRulePage;
