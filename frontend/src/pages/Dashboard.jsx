import React, { useState, useEffect } from 'react';
import axios from 'axios';

const Dashboard = () => {
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [threatLogs, setThreatLogs] = useState([]);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const onlineRes = await axios.get('http://127.0.0.1:8000/dashboard/online/');
        setOnlineUsers(onlineRes.data);

        const threatRes = await axios.get('http://127.0.0.1:8000/dashboard/threats/');
        setThreatLogs(threatRes.data);
      } catch (error) {
        console.error('대시보드 데이터를 불러오는 중 오류 발생:', error);
      }
    };

    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      <div className="page-header">
        <h2 className="page-title">📊 시스템 대시보드 (관제탑)</h2>
        <p className="page-subtitle">
          사내 네트워크 접근 제어 현황을 실시간으로 모니터링합니다. 
          <span style={{ color: '#10b981', fontWeight: 'bold', marginLeft: '10px' }}>● 실시간 DB 연동 중</span>
        </p>
      </div>
      
      <div className="card-grid">
        {/* 접속 현황 카드 */}
        <div className="card">
          <h3 className="card-title">
            <span>🟢</span> 현재 접속 중인 사원
          </h3>
          <table className="custom-table">
            <thead>
              <tr>
                <th>이름</th>
                <th>할당 IP</th>
                <th>접속 시간</th>
              </tr>
            </thead>
            <tbody>
              {onlineUsers.length > 0 ? onlineUsers.map(user => (
                <tr key={user.id}>
                  <td style={{ fontWeight: '600' }}>{user.emp_name}</td>
                  {/* 💡 IP 주소에 초록색 배지 디자인 적용 */}
                  <td><span className="badge badge-green">{user.ip}</span></td>
                  <td style={{ color: '#64748b' }}>{user.login_time}</td>
                </tr>
              )) : (
                <tr><td colSpan="3" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>현재 접속 기록이 없습니다.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* 위협 탐지 카드 */}
        <div className="card" style={{ borderTop: '4px solid #ef4444' }}>
          <h3 className="card-title text-danger">
            <span>🚨</span> 위협 탐지 로그 (차단됨)
          </h3>
          <table className="custom-table">
            <thead>
              <tr>
                <th>위반 사원</th>
                <th>차단된 목적지</th>
                <th>탐지 시간</th>
              </tr>
            </thead>
            <tbody>
              {threatLogs.length > 0 ? threatLogs.map(log => (
                <tr key={log.id}>
                  <td className="text-danger">{log.violator}</td>
                  {/* 💡 차단 도메인에 빨간색 배지 디자인 적용 */}
                  <td><span className="badge badge-red">{log.blocked_domain}</span></td>
                  <td style={{ color: '#64748b' }}>{log.time}</td>
                </tr>
              )) : (
                <tr><td colSpan="3" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>위협 탐지 기록이 없습니다.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;