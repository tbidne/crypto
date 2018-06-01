module RSASpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Random (newStdGen)
import Test.Hspec

import qualified RSA

spec :: Spec
spec = do
  describe "key to byte string" $ do
    it "should successfully convert the key" $ do
      g <- newStdGen
      let key = fromJust $ RSA.keygen g 2048
      let keyBytes = RSA.rsaKeyToByteString key
      let key' = RSA.byteStringToRsaKey keyBytes
      let m = RSA.modulus key
      let m' = RSA.modulus key'
      let e = RSA.publicExp key
      let e' = RSA.publicExp key'
      let d = RSA.privateExp key
      let d' = RSA.privateExp key'
      m' `shouldBe` m
      e' `shouldBe` e
      --d' `shouldBe` d