/**
 * @file BoardPage.jsx
 * @description 사내 자유 게시판 페이지입니다.
 * 임직원들이 자유롭게 의견을 나누고 정보를 공유할 수 있는 공간입니다.
 */

import React, { useState } from 'react';
import './BoardPage.css';

const BoardPage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: '/api/posts?category=일반' (GET) 엔드포인트에서 게시물 목록을 불러옵니다.
  const [posts, setPosts] = useState([
    { post_id: 105, category: '일반', title: '이번 달 회식 장소 추천받습니다.', author_name: '이영업', date: '2026-09-29', views: 42 },
    { post_id: 104, category: '일반', title: 'VSCode 새로운 확장프로그램 공유해요', author_name: '최프론트', date: '2026-09-28', views: 128 },
    { post_id: 103, category: '일반', title: '구내식당 메뉴 건의드립니다.', author_name: '김철수', date: '2026-09-27', views: 85 }
  ]);

  return (
    <div className="board-content-wrapper">
      <div className="board-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>사내 게시판</h3>
          <p>임직원 자유 소통 공간입니다. 상호 존중하는 문화를 만들어갑시다.</p>
        </div>
        <button
          style={{ backgroundColor: '#3498db', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer' }}
        >
          ✏️ 글쓰기
        </button>
      </div>

      <table className="board-table">
        <thead>
          <tr>
            <th>번호</th>
            <th>분류</th>
            <th style={{ width: '50%' }}>제목</th>
            <th>작성자</th>
            <th>작성일</th>
            <th>조회</th>
          </tr>
        </thead>
        <tbody>
          {posts.map(post => (
            <tr key={post.post_id}>
              <td>{post.post_id}</td>
              <td>{post.category}</td>
              <td style={{ textAlign: 'left', fontWeight: 'bold', cursor: 'pointer' }}>
                {post.title}
              </td>
              <td>{post.author_name}</td>
              <td>{post.date}</td>
              <td>{post.views}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* 💡 [DB 연동 포인트] 향후 페이징(Pagination) 컴포넌트가 추가될 자리입니다. */}
      <div className="pagination" style={{ textAlign: 'center', marginTop: '20px', color: '#7f8c8d' }}>
        <span>&lt; 1 2 3 &gt;</span>
      </div>
    </div>
  );
};

export default BoardPage;
