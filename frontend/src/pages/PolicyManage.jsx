import React, { useState, useEffect } from 'react';
import axios from 'axios';

const PolicyManage = () => {
  const [policies, setPolicies] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const [newIp, setNewIp] = useState('');

  const fetchPolicies = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/policies/blocklist/');
      setPolicies(response.data);
    } catch (error) {
      console.error('정책 목록을 불러오는 중 오류 발생:', error);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleAddPolicy = async (e) => {
    e.preventDefault();
    if (!newDomain || !newIp) {
      alert('차단할 도메인과 IP를 모두 입력해주세요.');
      return;
    }

    try {
      const response = await axios.post('http://127.0.0.1:8000/policies/add/', {
        no_access_domain: newDomain,
        no_access_ip: newIp
      });
      
      if (response.status === 201) {
        alert('차단 정책이 성공적으로 등록되었습니다.');
        setNewDomain('');
        setNewIp('');
        fetchPolicies();
      }
    } catch (error) {
      alert('정책 등록 중 오류가 발생했습니다.');
      console.error(error);
    }
  };

  return (
    <div className="dashboard-container" style={{ maxWidth: '900px' }}>
      <div className="page-header">
        <h2 className="page-title">🛡️ 차단 정책 (블랙리스트) 관리</h2>
        <p className="page-subtitle">
          등록된 도메인 및 IP는 패킷 감시 엔진에 의해 사내망 접근이 전면 차단됩니다.
        </p>
      </div>

      {/* 새 정책 등록 폼 (카드 레이아웃 적용) */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <h3 className="card-title" style={{ fontSize: '16px', marginBottom: '15px' }}>
          ➕ 새 차단 정책 등록
        </h3>
        <form onSubmit={handleAddPolicy} style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
          <input 
            type="text" 
            className="custom-input"
            placeholder="도메인 (예: warning.or.kr)" 
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
          />
          <input 
            type="text" 
            className="custom-input"
            placeholder="차단 IP (예: 121.189.10.1)" 
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
          />
          <button type="submit" className="btn-primary">
            차단 등록
          </button>
        </form>
      </div>

      {/* 정책 목록 표 (카드 레이아웃 및 디자인 표 적용) */}
      <div className="card">
        <table className="custom-table">
          <thead>
            <tr>
              <th>차단 도메인 (Domain)</th>
              <th>차단 대상 IP</th>
            </tr>
          </thead>
          <tbody>
            {policies.length > 0 ? (
              policies.map((policy, index) => (
                <tr key={index}>
                  {/* 💡 도메인에 빨간색 배지 적용 */}
                  <td><span className="badge badge-red">{policy.no_access_domain}</span></td>
                  <td style={{ fontWeight: '500' }}>{policy.no_access_ip}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="2" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
                  현재 등록된 차단 정책이 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default PolicyManage;