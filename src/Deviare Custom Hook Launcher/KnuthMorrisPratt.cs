using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Deviare_Custom_Handler_Sample
{
    class KnuthMorrisPratt
    {
        private string _ss = null;
        private int[] _table = null;

        public KnuthMorrisPratt(string ss)
        {
            this._ss = ss;
            this.BuildTable(this._ss);
        }

        public int Search(IntPtr str, uint length)
        {
            int m = 0;
            int i = 0;


            while (m + i < length)
            {
                byte buffer_byte = Marshal.ReadByte(str, m + i);

                if (this._ss[i] == buffer_byte)
                {
                    if (i == _ss.Length - 1)
                    {
                        return m;
                    }

                    i += 1;
                }
                else
                {
                    m += i - this._table[i]; /* *** */

                    if (this._table[i] > -1)
                        i = this._table[i];
                    else
                        i = 0;
                }
            }

            return -1;
        }

        private void BuildTable(string ss)
        {
            int pos = 2;
            int cnd = 0;

            this._table = new int[ss.Length];

            _table[0] = -1;
            _table[1] = 0;

            while (pos < ss.Length)
            {
                if (ss[pos - 1] == ss[cnd])
                {
                    cnd += 1;
                    this._table[pos] = cnd;
                    pos += 1;
                }
                else if (cnd > 0)
                {
                    cnd = this._table[cnd];
                }
                else
                {
                    this._table[pos] = 0;
                    pos += 1;
                }
            }
            
        }
    }
}
