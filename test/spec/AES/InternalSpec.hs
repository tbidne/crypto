module AES.InternalSpec
( spec
)
where

--import qualified Data.ByteString.Lazy as BS (append)
--import System.Random as R (newStdGen)
import Test.Hspec

--import qualified Common as C
import AES.Internal

spec :: Spec
spec = do
  describe "rotate" $ do
    it "should rotate the list by one" $ do
      rotate ([1,2,3,4,5]::[Int]) `shouldBe` ([2,3,4,5,1]::[Int])

  describe "fieldMult" $ do
    it "should multiply by 2 in GF(2^8)" $ do
      fieldMult 2 57 `shouldBe` 114
      fieldMult 2 128 `shouldBe` 27
    it "should multiply by 3 in GF(2^8)" $ do
      fieldMult 3 8 `shouldBe` 24
      fieldMult 3 200 `shouldBe` 67
    it "should multiply by 9 in GF(2^8)" $ do
      fieldMult 9 4 `shouldBe` 36
      fieldMult 9 200 `shouldBe` 210
    it "should multiply by 11 in GF(2^8)" $ do
      fieldMult 11 4 `shouldBe` 44
      fieldMult 11 128 `shouldBe` 247
    it "should multiply by 13 in GF(2^8)" $ do
      fieldMult 13 4 `shouldBe` 52
      fieldMult 13 128 `shouldBe` 218
    it "should multiply by 14 in GF(2^8)" $ do
      fieldMult 14 4 `shouldBe` 56
      fieldMult 14 128 `shouldBe` 65
    it "should return 0 for wrong params" $ do
      fieldMult 0 4 `shouldBe` 0
      fieldMult 5 7 `shouldBe` 0
