{-|
Module      : RSA.API
Description : Internal functions used for RSA
License     : MIT
Maintainer  : tbidne@gmail.com

Internal functions used for RSA
-}
module RSA.Internal
( Key (..)
, keyToByteString
, byteStringToKey
, genModulus
)
where

import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append)
import           System.Random (RandomGen)
import           System.Random as R (next)

import qualified Common as C
import qualified NumberTheory as NT

-- | An internal representation of an RSA key.
data Key = Key {
  keyModulus :: !Integer
, keyExponent :: !Integer
} deriving (Eq, Show)

-- | Transforms a 'Key' into a 'ByteString'.
keyToByteString :: Key -> ByteString
keyToByteString key = eBytes `BS.append` mBytes
  where  eBytes = C.intToByteString (keyExponent key)
         mBytes = C.intToByteString (keyModulus key)

-- | Transforms a 'ByteString' into a 'Key'.
byteStringToKey :: ByteString -> Key
byteStringToKey keyBytes = key
  where (e, mBS) = C.byteStringToInt keyBytes
        (m,_) = C.byteStringToInt mBS
        key = Key {keyModulus = m, keyExponent = e}  

-- | For a 'RandomGen' @g@ and @b@ bit-length, returns
-- @(p, q)@, for primes @p@ and @q@.
genModulus :: (RandomGen a, Integral b) => a -> b -> (Integer, Integer)
genModulus g size = (p, q)
  where p = NT.genPrime g $ size `div` 2
        q = NT.genPrime g' $ size `div` 2
        g' = snd $ R.next g