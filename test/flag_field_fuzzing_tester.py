## This file tests the changes made to the fuzz function that
## allow it to properly fuzz values for FlagField type fields.

import unittest

from scapy.all import *

class TestingFuzzingChanges(unittest.TestCase):

   def test_flag_bounds(self):
      """
      This test ensures that the show function fails when a flag value that 
      exceeds the bounds of a given FlagField is or exceeds the result of
      2 ^ (FlagField length value). Thus ensuring that the logic used to 
      generate values for FlagField type fields holds.
      """
      tst = IP(flags = 8)
      with self.assertRaises(IndexError):
         tst.show()
      tst = IP(flags = -1)
      with self.assertRaises(IndexError):
         tst.show()
      tst = TCP(flags = 256)
      with self.assertRaises(IndexError):
         tst.show()
      tst = TCP(flags = -1)
      with self.assertRaises(IndexError):
         tst.show()

   def test_ip_fuzzing(self):
      tst = fuzz(IP())
      self.assertIsNotNone(tst.flags,
                           msg="Field value not succesfully generated.")
      self.assertTrue(tst.flags >= 0 and tst.flags < 8, 
                      msg="Fuzzed value exceeds field boundaries.")
      # Ensure that fuzzing still works if the flags are preset
      tst = fuzz(IP(flags=7))
      self.assertTrue(tst.flags == 7,
                      msg="Fuzzing overwrote specified flag value.")
      # Ensure that the original issue was fixed
      try:
         fuzz(IP()).show()
      except TypeError:
         self.fail("TypeError Exception occurred; original issue not resolved")

   
   def test_tcp_fuzzing(self):
      tst = fuzz(TCP())
      self.assertIsNotNone(tst.flags, 
                           msg="Field value not succesfully generated.")
      self.assertTrue(tst.flags >= 0 and tst.flags < 256,
                      msg="Fuzzed value exceeds field boundaries.")
      # Ensure that fuzzing still works if the flags are preset
      tst = fuzz(TCP(flags=255))
      self.assertTrue(tst.flags == 255,
                      msg="Fuzzing overwrote specified flag value.")
      # Ensure that the original issue was fixed
      try:
         fuzz(TCP()).show()
      except TypeError:
         self.fail("TypeError Exception occurred; original issue not resolved")

   

if __name__ == '__main__':
   unittest.main()
