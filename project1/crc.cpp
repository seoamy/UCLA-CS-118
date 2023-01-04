#include <iostream>
#include <unistd.h>
#include <unordered_set>

using namespace std;
static const string cvGenerator = "10001000010100001"; // x16 + x12 + x7 + x5 + 1
static const string ftGenerator = "11001000000000101"; // x16 + x15 + x12 + x2 + 1
static const string pGenerator = "11000000000000101";  // x16 + x15 + x2 + 1

string XOR(string s1, string s2)
{
  string result = "";
  int length = s2.length();

  for (int i = 1; i < length; i++)
  {
    if (s1[i] == s2[i])
    {
      result += "0";
    }
    else
    {
      result += "1";
    }
  }
  return result;
}

string calculateCRC(string bitstring, string generator)
{
  int endbit = generator.length();
  string remainder = bitstring.substr(0, endbit);
  int n = bitstring.length();

  while (endbit < n)
  {
    if (remainder[0] == '1')
    { // XOR with the generator
      remainder = XOR(generator, remainder) + bitstring[endbit];
    }
    else
    { // XOR with 0s
      remainder = XOR(std::string(endbit, '0'), remainder) + bitstring[endbit];
    }
    endbit += 1;
  }

  if (remainder[0] == '1')
  {
    remainder = XOR(generator, remainder);
  }
  else
  {
    remainder = XOR(std::string(endbit, '0'), remainder);
  }
  return remainder;
}

string appendCRC(string bitstring, string g)
{
  int length = g.length();
  string appended_bitstring = (bitstring + std::string(length - 1, '0'));
  string remainder = calculateCRC(appended_bitstring, g);
  return bitstring + remainder;
}

string validateCRC(string bitstring, string g)
{
  string msgWithoutCRC = bitstring.substr(0, bitstring.length() - g.length() + 1);
  string calculatedMsgWithCRC = appendCRC(msgWithoutCRC, g);
  if (calculatedMsgWithCRC == bitstring)
  {
    return "1";
  }
  else
  {
    return "0";
  }
}

void find4bitErrors(string bitstring, string g)
{
  string bitstringWithCRC = appendCRC(bitstring, g);
  int length = bitstringWithCRC.length();
  unordered_set<string> undetectedErrorsSet;

  for (int i = 0; i < length; i++)
  {
    // change 1st bit
    bool i0 = true;
    if (bitstringWithCRC[i] == '1')
    {
      i0 = false;
      bitstringWithCRC[i] = '0';
    }
    else
    {
      bitstringWithCRC[i] = '1';
    }
    for (int j = i; j < length; j++)
    {
      // change 2nd bit
      bool j0 = true;
      if (bitstringWithCRC[j] == '1')
      {
        j0 = false;
        bitstringWithCRC[j] = '0';
      }
      else
      {
        bitstringWithCRC[j] = '1';
      }
      for (int k = j; k < length; k++)
      {
        // change 3rd bit
        bool k0 = true;
        if (bitstringWithCRC[k] == '1')
        {
          k0 = false;
          bitstringWithCRC[k] = '0';
        }
        else
        {
          bitstringWithCRC[k] = '1';
        }
        for (int l = k + 1; l < length; l++)
        {
          // change 4th bit
          bool l0 = true;
          if (bitstringWithCRC[l] == '1')
          {
            l0 = false;
            bitstringWithCRC[l] = '0';
          }
          else
          {
            bitstringWithCRC[l] = '1';
          }
          // check if string is remainder 0 here
          string rem = calculateCRC(bitstringWithCRC, g);
          if (rem == std::string(g.length() - 1, '0'))
          {
            // cout << bitstringWithCRC << endl;
            undetectedErrorsSet.insert(bitstringWithCRC);
          }

          // change 4th bit back
          if (l0)
          { // back to 0
            bitstringWithCRC[l] = '0';
          }
          else
          {
            bitstringWithCRC[l] = '1';
          }
        }
        // change 3rd bit back
        if (k0)
        { // back to 0
          bitstringWithCRC[k] = '0';
        }
        else
        {
          bitstringWithCRC[k] = '1';
        }
      }
      // change 2nd bit back
      if (j0)
      { // back to 0
        bitstringWithCRC[j] = '0';
      }
      else
      {
        bitstringWithCRC[j] = '1';
      }
    }
    // change 1st bit back
    if (i0)
    { // back to 0
      bitstringWithCRC[i] = '0';
    }
    else
    {
      bitstringWithCRC[i] = '1';
    }
  }
  // print out all undetected errors in set
  unordered_set<string>::iterator itr;
  for (itr = undetectedErrorsSet.begin(); itr != undetectedErrorsSet.end(); itr++){
    if (*itr != bitstringWithCRC) {
      cout << *itr << endl;
    }
  }
}

void find5bitErrors(string bitstring, string g) { 
  string bitstringWithCRC = appendCRC(bitstring, g);
  int length = bitstringWithCRC.length();
  unordered_set<string> undetectedErrorsSet;

  for (int h = 0; h < length; h++) {
    // change 1st bit
    bool h0 = true;
    if (bitstringWithCRC[h] == '1') {
      h0 = false;
      bitstringWithCRC[h] = '0';
    } else {
      bitstringWithCRC[h] = '1';
    }
    for (int i = h; i < length; i++)
    {
      // change 2nd bit
      bool i0 = true;
      if (bitstringWithCRC[i] == '1')
      {
        i0 = false;
        bitstringWithCRC[i] = '0';
      }
      else
      {
        bitstringWithCRC[i] = '1';
      }
      for (int j = i; j < length; j++)
      {
        // change 3rd bit
        bool j0 = true;
        if (bitstringWithCRC[j] == '1')
        {
          j0 = false;
          bitstringWithCRC[j] = '0';
        }
        else
        {
          bitstringWithCRC[j] = '1';
        }
        for (int k = j; k < length; k++)
        {
          // change 4th bit
          bool k0 = true;
          if (bitstringWithCRC[k] == '1')
          {
            k0 = false;
            bitstringWithCRC[k] = '0';
          }
          else
          {
            bitstringWithCRC[k] = '1';
          }
          for (int l = k + 1; l < length; l++)
          {
            // change5th bit
            bool l0 = true;
            if (bitstringWithCRC[l] == '1')
            {
              l0 = false;
              bitstringWithCRC[l] = '0';
            }
            else
            {
              bitstringWithCRC[l] = '1';
            }
            // check if string is remainder 0 here
            string rem = calculateCRC(bitstringWithCRC, g);
            if (rem == std::string(g.length() - 1, '0'))
            {
              undetectedErrorsSet.insert(bitstringWithCRC);
            }

            // change 5th bit back
            if (l0)
            { // back to 0
              bitstringWithCRC[l] = '0';
            }
            else
            {
              bitstringWithCRC[l] = '1';
            }
          }
          // change 4th bit back
          if (k0)
          { // back to 0
            bitstringWithCRC[k] = '0';
          }
          else
          {
            bitstringWithCRC[k] = '1';
          }
        }
        // change 3rd bit back
        if (j0)
        { // back to 0
          bitstringWithCRC[j] = '0';
        }
        else
        {
          bitstringWithCRC[j] = '1';
        }
      }
      // change 2nd bit back
      if (i0)
      { // back to 0
        bitstringWithCRC[i] = '0';
      }
      else
      {
        bitstringWithCRC[i] = '1';
      }
    }
    // change 1st bit back
    if (h0) {
      bitstringWithCRC[h] = '0';
    } else {
      bitstringWithCRC[h] = '1';
    }
  }

  // count all undetected 5-bit errors
  int count = 0;
  unordered_set<string>::iterator itr;
  for (itr = undetectedErrorsSet.begin(); itr != undetectedErrorsSet.end(); itr++){
    if (*itr != bitstringWithCRC) {
      count++;
    }
  }
  cout << count << endl;
}

int main(int argc, char **argv)
{
  int flag;

  while ((flag = getopt(argc, argv, "c:v:f:t:p:")) != -1)
  {
    switch (flag)
    {
    case 'c':
      // The  program  must  accept  a  string  as  argument  provided  in  the  format  -c  [string
      // representing  bits  e.g.  01010101].  It  must  then  output  the  correct  bitstring  WITH  the
      // attached CRC to stdout, using the generator x16 + x12 + x7 + x5 + 1.
      // cout << bitstringWithCRC(optarg, cvGenerator) << endl;
      cout << appendCRC(optarg, cvGenerator) << endl;
      break;
    case 'v':
      // The  program  must  accept  a  string  as  argument  provided  in  the  format  -v  [string
      // representing  bits  e.g.  01010101].  It  must  then  validate  whether  or  not  the  string  is
      // consistent with the attached CRC, using the generator x16 + x12 + x7 + x5 + 1. In case of a
      // valid input, the program should output a ‘1’ to stdout, and if invalid, should output a ‘0’.
      cout << validateCRC(optarg, cvGenerator) << endl;
      break;
    case 'f':
      // The  program  must  accept  a  string  as  argument  provided  in  the  format  -f  [string 
      // representing bits, e.g. 01010101]. The input string will include a message without a CRC. 
      // It must then output all undetected 4 bit errors to stdout, with new-line characters between 
      find4bitErrors(optarg, ftGenerator);
      break;
    case 't':
      // The  program  must  accept  a  string  as  argument  provided  in  the  format  -t  [string 
      // representing  bits,  e.g.  01010101].  It  must  then  output  a  single  non-negative  integer, 
      // denoting  the  number  of  undetected  5-bit  errors  to  stdout.  As  above,  the  input  will  be  a 
      // message without a CRC. The generator polynomial to be used in this part is x16 + x15 + 
      // x12 + x2 + 1.
      find5bitErrors(optarg, ftGenerator);
      break;
    case 'p':
      // The  program  must  accept  a  string  as  argument  provided  in  the  format  -p  [string
      // representing  bits,  e.g.  01010101].  It  must  then  output  a  single  non-negative  integer,
      // denoting  the  number  of  undetected  5-bit  errors  to  stdout.  As  above,  the  input  will  be  a
      // message without a CRC. The generator polynomial to be used in this part is x16 + x15 + x2 + 1.

      // x16 + x15 + x2 + 1 is divisible by (x+1), so g can detect all odd bit errors, so it detects all 5-bit errors.
      // Therefore, the number of undetected 5-bit errors will be 0.
      cout << 0 << endl;
      break;
    }
  }
  return 0;
}