using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;

namespace Deviare_Custom_Handler_Sample
{
    public partial class Form1 : Form
    {
        HookingManager _hooking_manager = null;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            bool custom_hook = false;

            switch (this.comboBox1.SelectedIndex)
            {
                case 0:
                    custom_hook = true;
                    break;

                case 1:
                    custom_hook = false;
                    break;
            }
            this._hooking_manager.Hook(custom_hook);
            this.button1.Enabled = false;
            this.comboBox1.Enabled = false;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this._hooking_manager = new HookingManager();
            this.comboBox1.SelectedIndex = 0;
        }
    }
}
