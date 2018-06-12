module RSA.APISpec
( spec
)
where

import Data.ByteString.Lazy (unpack)
import Data.Maybe (fromJust, isNothing)
import System.Random (newStdGen)
import Test.Hspec

import qualified RSA.API as RSA

spec :: Spec
spec = do
  describe "keygen" $ do
    it "should generate 1024 bit key" $ do
      keygen 1024 135 260

    it "should generate 2048 bit key" $ do
      keygen 2048 263 516

    it "should return Nothing for wrong bit key" $ do
      g <- newStdGen
      let key = RSA.keygen g (1000 :: Integer)
      isNothing key `shouldBe` True

keygen :: Int -> Int -> Int -> Expectation
keygen sizeInBits expectedPk expectedSk = do
  g <- newStdGen
  let key = RSA.keygen g sizeInBits
  let (pk, sk) = fromJust key
  let pkLen = length $ unpack pk
  let skLen = length $ unpack sk
  pkLen `shouldSatisfy` (\x -> x `elem` [expectedPk-1..expectedPk+1])
  skLen `shouldSatisfy` (\x -> x `elem` [expectedSk-1..expectedSk+1])