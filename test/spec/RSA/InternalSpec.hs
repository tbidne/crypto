module RSA.InternalSpec
( spec
)
where

import qualified Data.ByteString.Lazy as BS (append)
import System.Random as R (newStdGen)
import Test.Hspec

import qualified Common as C
import RSA.Internal

spec :: Spec
spec = do
  describe "key / bytestring conversions" $ do
    it "should convert key to bytestring" $ do
      let key = Key {keyModulus = 1000, keyExponent = 200}
      let expected = C.intToByteString 200 `BS.append` C.intToByteString 1000
      keyToByteString key `shouldBe` expected
    it "should convert bytestring to key" $ do
      let expected = Key {keyModulus = 1000, keyExponent = 200}
      let bytes = C.intToByteString 200 `BS.append` C.intToByteString 1000
      byteStringToKey bytes `shouldBe` expected

  describe "genModulus" $ do
    it "should generate a modulus in range" $ do
      g <- R.newStdGen
      let (p,q) = genModulus g 512
      p `shouldSatisfy` (\x -> x >= 2^255 && x < 2^256)
      q `shouldSatisfy` (\x -> x >= 2^255 && x < 2^256)