{-# LANGUAGE GADTs #-}

{-|
Module      : Common
Description : Internal functions used for AES
License     : MIT
Maintainer  : tbidne@gmail.com

Internal functions used for AES.
-}
module AES.Internal
( ecb
, encryptInit
, decryptInit
, fieldMult
, rotate
, setupForTransform
, KeyError(..)
, AESError(..)
)
where

import           Data.Bits ()
import qualified Data.Bits as B (shiftL, xor, (.&.))
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, pack, unpack, empty)
import           Data.Word (Word8)
import           Prelude hiding (round)

import Data.Vector (slice)

import AES.Key
import AES.State (State, flatListToState, transpose, shiftRows, invShiftRows, subSWords, invSubSWords, xorSK)
import AES.Common

---------------------------------
-- Block Cipher Mode Functions --
---------------------------------

data AESError where
  AESKey :: KeyError -> AESError
  deriving Show

-- | Takes an 'Int' @maxRound@, encryption function @f@, [['Word8']] @roundKeys@,
-- ['Word8'] message, and starting matrix []. Encrypts each block with @f@ and
-- concatenates all blocks together.
ecb :: (KeySchedule -> State (V4 Word8) -> State (V4 Word8))
    -> KeySchedule
    -> [Word8]
    -> [State (V4 Word8)]
    -> ByteString
ecb _ _ [] encrypted = foldr (\a b -> BS.append a b) BS.empty $ fmap stateToByteStr encrypted
ecb f ks bytes encrypted = ecb f ks bytes' encrypted'
  where state = flatListToState $ take 16 bytes
        bytes' = drop 16 bytes
        encrypted' = f ks state : encrypted

--------------------
-- Init Functions --
--------------------

-- | For 'ByteString' @key@, returns @(maxRound, roundKeys)@.
setupForTransform :: ByteString -> Either KeyError KeySchedule
setupForTransform k = (flatListToKeySchedule . BS.unpack) k

--------------------------------
-- Rijndael Encrypt Functions --
--------------------------------

-- | Round 0
-- Takes an 'Int' @maxRound@, [['Word8']] @roundKeys@,
-- ['Word8'] state, and returns the modified state.
encryptInit :: KeySchedule -> State (V4 Word8) -> State (V4 Word8)
encryptInit ks state = encryptRound 1 ks state'
  where state' = addRoundKey 0 ks state

-- | Rounds 1 to Nr-1
-- Takes 'Int's @round@ for the currentRound, @maxRound@, [['Word8']] @ks@,
-- ['Word8'] state. Modifies the state according to FIPS 197, returns the
-- state after round Nr-1.
encryptRound :: Int -> KeySchedule -> State (V4 Word8) -> State (V4 Word8)
encryptRound round ks state
  | round == (toNr ks) = encryptFinalize round ks state
  | otherwise                 = encryptRound (round+1) ks state'
  where transform = mixColumns . shiftRows . subSWords
        state' = addRoundKey round ks $ transform state

-- | Round Nr: final round
-- Takes 'Int' @round@, [['Word8']] @roundKeys@, ['Word8'] state.
-- Performs the final transformation and returns the state.
encryptFinalize :: Int -> KeySchedule -> State (V4 Word8) -> State (V4 Word8)
encryptFinalize round ks state = state'
  where transform = shiftRows . subSWords
        state' = addRoundKey round ks $ transform state

-- Mixes columns based on below affine transformation
mixColumns :: State (V4 Word8) -> State (V4 Word8)
mixColumns = transpose . fmap affineTransform . transpose

--------------------------------
-- Rijndael Decrypt Functions --
--------------------------------

-- | Round Nr
-- Takes an 'Int' @maxRound@, [['Word8']] @roundKeys@,
-- ['Word8'] state, and returns the modified state.
decryptInit :: KeySchedule -> State (V4 Word8) -> State (V4 Word8)
decryptInit ks state = decryptRound ((toNr ks) - 1) ks state'
  where state' = addRoundKey (toNr ks) ks state

-- Rounds Nr-1 to 1
decryptRound :: Int -> KeySchedule -> State (V4 Word8) -> State (V4 Word8)
decryptRound 0 ks state = decryptFinalize ks state
decryptRound round ks state = decryptRound (round-1) ks state'
  where transform = invSubSWords . invShiftRows
        state' = invMixColumns $ addRoundKey round ks $ transform state

-- Round 0: final transformation
decryptFinalize :: KeySchedule -> State (V4 Word8) -> State (V4 Word8)
decryptFinalize ks state = state'
  where transform = invSubSWords . invShiftRows
        state' = addRoundKey 0 ks $ transform state

-- Mixes columns based on below inverse affine transformation
invMixColumns :: State (V4 Word8) -> State (V4 Word8)
invMixColumns = transpose . fmap invAffineTransform . transpose

------------------------------
-- Other Rijndael Functions --
------------------------------

-- xors the State (V4 Word8) with the current round key
addRoundKey :: Int -> KeySchedule -> State (V4 Word8) -> State (V4 Word8)
addRoundKey r ks state = xorSK state t
  where lowIdx = 4 * r
        rk = slice lowIdx 4 (exposeKS ks)
        t = vTranspose rk

----------------------
-- Helper Functions --
----------------------

-- | We only need to implement multiplication by 2 and 3 in GF(2^8) for encryption,
-- 9, 11, 13, and 14 for decryption.
-- Multiplication by 2 is equivalent to bit shifting by one and adding (xor)
-- 0x1b (27) if the high bit was set.
-- 3 x b = (2 xor 1) b = (2 x b) xor b
fieldMult :: Word8 -> Word8 -> Word8
fieldMult 2 b
  | highBitSet = shifted `B.xor` 27 -- 27 = x^4 + x^3 + x + 1 
  | otherwise  = shifted
  where shifted = b `B.shiftL` 1
        highBitSet = b B..&. 128 == 128
fieldMult 3 b = B.xor b (fieldMult 2 b) -- 3 x b = (2 x b) xor b
fieldMult 9 b =  B.xor b (fieldMult 2 (fieldMult 2 (fieldMult 2 b)))
fieldMult 11 b = B.xor b (fieldMult 2 (B.xor b (fieldMult 2 (fieldMult 2 b))))
fieldMult 13 b = B.xor b (fieldMult 2 (fieldMult 2 (B.xor b (fieldMult 2 b))))
fieldMult 14 b = fieldMult 2 (B.xor b (fieldMult 2 (B.xor b (fieldMult 2 b))))
fieldMult _ _ = 0

-- Performs an affine transformation on the param vector based on the matrix
-- | 2 3 1 1 |
-- | 1 2 3 1 |
-- | 1 1 2 3 |
-- | 3 1 1 2 |
-- Addition is xor and multiplication is in GF(2^8).
affineTransform :: V4 Word8 -> V4 Word8
affineTransform (V4 w0 w1 w2 w3) = V4 bOne bTwo bThree bFour
  where bOne =   fieldMult 2 w0 `B.xor`
                 fieldMult 3 w1 `B.xor`
                 w2 `B.xor`
                 w3
        bTwo =   w0 `B.xor`
                 fieldMult 2 w1 `B.xor`
                 fieldMult 3 w2 `B.xor`
                 w3
        bThree = w0 `B.xor`
                 w1 `B.xor`
                 fieldMult 2 w2 `B.xor`
                 fieldMult 3 w3
        bFour =  fieldMult 3 w0 `B.xor`
                 w1 `B.xor`
                 w2 `B.xor`
                 fieldMult 2 w3

-- Performs an affine transformation on the param vector based on the matrix
-- | 14 11 13  9 |
-- | 9  14 11 |3 |
-- | 13 9  14 11 |
-- | 11 13 9  14 |
-- Addition is xor and multiplication is in GF(2^8).
invAffineTransform :: V4 Word8 -> V4 Word8
invAffineTransform (V4 w0 w1 w2 w3) = V4 bOne bTwo bThree bFour
  where bOne =   fieldMult 14 w0 `B.xor`
                 fieldMult 11 w1 `B.xor`
                 fieldMult 13 w2 `B.xor`
                 fieldMult 9  w3
        bTwo =   fieldMult 9  w0 `B.xor`
                 fieldMult 14 w1 `B.xor`
                 fieldMult 11 w2 `B.xor`
                 fieldMult 13 w3
        bThree = fieldMult 13 w0 `B.xor`
                 fieldMult 9  w1 `B.xor`
                 fieldMult 14 w2 `B.xor`
                 fieldMult 11 w3
        bFour =  fieldMult 11 w0 `B.xor`
                 fieldMult 13 w1 `B.xor`
                 fieldMult 9  w2 `B.xor`
                 fieldMult 14 w3

-- Returns a bytestring based on the state matrix.
stateToByteStr :: State (V4 Word8) -> ByteString
stateToByteStr = BS.pack . mconcat . fmap toList . toList . transpose