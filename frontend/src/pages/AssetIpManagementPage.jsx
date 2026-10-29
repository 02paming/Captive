/**
 * @file AssetIpManagementPage.jsx
 * @description [관리자 전용] IT 자산 및 IP 관리 페이지입니다.
 * 사내망에 연결된 기기들의 IP 주소와 할당받은 부서/사용자 정보를 중앙에서 통제합니다.
 */

import React, { useState } from 'react';
import './AssetIpManagementPage.css'; // 기존 CSS 유지

const AssetIpManagementPage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: '/api/admin/assets' (GET) 엔드포인트에서 자산 목록을 불러옵니다.
  // DB의 assets 테이블과 1:1로 매칭되는 구조입니다.
  const [assets, setAssets] = useState([
    { asset_id: 1, ip_address: '192.168.1.10', device_name: 'PC-SEC-01', owner_name: '윤두상', department: '보안1팀', status: '사용중' },
    { asset_id: 2, ip_address: '192.168.1.11', device_name: 'PC-SEC-02', owner_name: '최프론트', department: '보안1팀', status: '사용중' },
    { asset_id: 3, ip_address: '192.168.1.55', device_name: 'PC-HR-01', owner_name: '홍길동', department: '인사팀', status: '사용중' },
    { asset_id: 4, ip_address: '192.168.1.99', device_name: 'LAPTOP-GUEST', owner_name: '공용기기', department: '경영지원실', status: '회수됨' }
  ]);

  return (
    <div className="asset-container">
      <div className="asset-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>IT 자산 / IP 관리 대장</h3>
          <p>사내 네트워크 IP 할당 현황 및 지급된 하드웨어 자산을 관리합니다.</p>
        </div>
        <button
          style={{ backgroundColor: '#2c3e50', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer' }}
        >
          + 신규 자산 등록
        </button>
      </div>

      <table className="board-table">
        <thead>
          <tr>
            <th>No.</th>
            <th>할당 IP 주소</th>
            <th>기기명 (Host)</th>
            <th>사용자</th>
            <th>소속 부서</th>
            <th>상태</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset, index) => (
            <tr key={asset.asset_id}>
              <td>{index + 1}</td>
              <td style={{ fontWeight: 'bold', color: '#2980b9' }}>{asset.ip_address}</td>
              <td>{asset.device_name}</td>
              <td>{asset.owner_name}</td>
              <td>{asset.department}</td>
              <td>
                <span className={`status-badge ${asset.status === '사용중' ? 'approved' : 'rejected'}`}>
                  {asset.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AssetIpManagementPage;
