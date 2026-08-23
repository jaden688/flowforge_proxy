import React from 'react';
import { DecoderDrawer } from './DecoderDrawer';

export interface MultiLayerDecoderModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialInput?: string;
}

export const MultiLayerDecoderModal: React.FC<MultiLayerDecoderModalProps> = ({
  isOpen,
  onClose,
  initialInput = '',
}) => {
  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div 
        onClick={onClose} 
        className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 transition-opacity" 
      />
      
      {/* Drawer */}
      <DecoderDrawer 
        isOpen={isOpen} 
        onClose={onClose} 
        initialInput={initialInput} 
      />
    </>
  );
};
