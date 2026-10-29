/**
 * 파일명: CustomModal.jsx
 * 역할: 브라우저 기본 alert, confirm을 대체하는 예쁜 디자인의 팝업 컴포넌트
 * 
 * [주요 프롭스(Props) 안내 - 부모 컴포넌트에서 전달받는 값들]
 * @param {boolean} isOpen - 모달창을 화면에 띄울지 말지 결정 (true면 보임)
 * @param {string} type - 'alert'(확인 버튼만) 또는 'confirm'(취소/확인 버튼 둘 다)
 * @param {string} title - 모달창 상단 제목
 * @param {string} message - 모달창 본문 내용
 * @param {function} onConfirm - '확인' 버튼을 눌렀을 때 실행될 함수
 * @param {function} onCancel - '취소' 버튼을 눌렀을 때 실행될 함수
 */

import React from 'react';
import './CustomModal.css';

const CustomModal = ({ isOpen, type, title, message, onConfirm, onCancel }) => {
  // isOpen이 false면 화면에 아무것도 그리지 않습니다.
  if (!isOpen) return null;

  return (
    // 배경을 어둡게 만들어주는 오버레이 영역
    <div className="modal-overlay">
      {/* 실제 하얀색 팝업 박스 */}
      <div className="modal-box">
        <h3 className="modal-title">{title}</h3>
        <p className="modal-message">{message}</p>

        <div className="modal-actions">
          {/* type이 'confirm'일 때만 '취소' 버튼을 화면에 보여줍니다. */}
          {type === 'confirm' && (
            <button className="modal-cancel-btn" onClick={onCancel}>
              취소
            </button>
          )}
          <button className="modal-confirm-btn" onClick={onConfirm}>
            확인
          </button>
        </div>
      </div>
    </div>
  );
};

export default CustomModal;
