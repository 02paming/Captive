/**
 * @file OrgChartPage.jsx
 * @description 전사 조직도 페이지입니다.
 * 부서별 인원 현황을 시각적인 트리 및 리스트 형태로 렌더링합니다.
 */

import React, { useState, useEffect } from 'react';
import './OrgChartPage.css';

// 트리를 그려주는 노드 컴포넌트 (이전의 세로형 리스트 로직 완벽 유지)
const TreeNode = ({ node }) => {
  if (node.members) {
    return (
      <li className="team-column-node">
        <div className="team-column">
          <div className="team-header">{node.deptName}</div>
          <div className="team-members-stack">
            {node.members.map((member, idx) => (
              <div className="list-card" key={idx}>
                <div className="list-avatar">{member.name.charAt(0)}</div>
                <div className="list-info">
                  <span className="list-name">{member.name}</span>
                  <span className="list-pos">{member.position}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </li>
    );
  }

  return (
    <li>
      <div className="node-wrapper">
        {node.deptName && <div className="dept-label">{node.deptName}</div>}
        <div className="member-card">
          <div className="member-avatar">{node.name.charAt(0)}</div>
          <div className="member-info">
            <span className="member-name">{node.name}</span>
            <span className="member-position">{node.position}</span>
          </div>
        </div>
      </div>
      {node.children && node.children.length > 0 && (
        <ul>{node.children.map((child, idx) => <TreeNode key={idx} node={child} />)}</ul>
      )}
    </li>
  );
};

const OrgChartPage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: '/api/users' (GET) 데이터를 가져와 아래의 계층형 트리(Tree) 구조로 재가공해야 합니다.
  const orgData = {
    name: '이대표', position: '대표이사',
    children: [
      {
        name: '김보안', position: '보안개발실장', deptName: '보안개발실',
        children: [
          { deptName: '보안1팀', members: [{ name: '윤두상', position: '팀장' }, { name: '최프론트', position: '선임연구원' }, { name: '박백엔드', position: '연구원' }] },
          { deptName: '보안관제팀', members: [{ name: '강네트', position: '팀장' }, { name: '송패킷', position: '주임연구원' }] }
        ]
      },
      {
        name: '박경영', position: '경영지원실장', deptName: '경영지원실',
        children: [
          { deptName: '인사팀', members: [{ name: '홍길동', position: '팀장' }, { name: '이노무', position: '대리' }] },
          { deptName: '영업팀', members: [{ name: '이영업', position: '팀장' }, { name: '정매출', position: '과장' }] }
        ]
      }
    ]
  };

  return (
    <div className="org-chart-container">
      <div className="org-header-area">
        <h3 className="org-title">SecureTech 전사 조직도</h3>
        <p className="org-desc">마우스로 가로로 스크롤하여 전체 조직을 확인할 수 있습니다.</p>
      </div>
      <div className="tree-scroll-container">
        <div className="org-tree">
          <ul><TreeNode node={orgData} /></ul>
        </div>
      </div>
    </div>
  );
};

export default OrgChartPage;
