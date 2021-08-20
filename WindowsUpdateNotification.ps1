Add-Type -AssemblyName System.Windows.Forms

$CNSWinUpdate = New-Object system.Windows.Forms.Form
$CNSWinUpdate.Text = "Upcoming Windows Updates"
$CNSWinUpdate.BackColor = "#ffffff"
$CNSWinUpdate.TopMost = $true
$CNSWinUpdate.Width = 650
$CNSWinUpdate.Height = 313
$CNSWinUpdate.ControlBox = $false
$CNSWinUpdate.FormBorderStyle = "Fixed3D"

$PictureBox4 = New-Object system.windows.Forms.PictureBox
$PictureBox4.Width = 183
$PictureBox4.ImageLocation = "https://ctplabtech.s3.us-west-2.amazonaws.com/Logos/Watermark_Lodging_Trust_Logo%20-%20Copy.jpg"
$PictureBox4.Height = 57
$PictureBox4.Width = 285
$PictureBox4.Height = 57
$PictureBox4.location = new-object system.drawing.point(15,10)
$CNSWinUpdate.controls.Add($PictureBox4)

$label5 = New-Object system.windows.Forms.Label
$label5.Text = "NOTICE: Your computer is scheduled to receive updates this evening. At the end of the day, please SAVE all work, log out and leave your system online. Thank you for your cooperation."
$label5.Width = 575
$label5.Height = 85
$label5.location = new-object system.drawing.point(42,100)
$label5.Font = "Microsoft Sans Serif,12"
$CNSWinUpdate.controls.Add($label5)

$OK = New-Object system.windows.Forms.Button
$OK.BackColor = "#315e78"
$OK.Text = "OK"
$OK.ForeColor = "#ffffff"
$OK.Width = 60
$OK.Height = 30
$OK.Visible = $false
$OK.Add_Click({
	"$($env:username) acknowledged update window" | out-file -filepath "$($env:windir)\temp\updatenotifresult.txt"
	$CNSWinUpdate.Dispose()
})
$OK.location = new-object system.drawing.point(401,222)
$OK.Font = "Microsoft Sans Serif,12,style=Bold"
$CNSWinUpdate.controls.Add($OK)

$label7 = New-Object system.windows.Forms.Label
$label7.Text = "If you have any questions, please email ithelpdesk@watermarklodging.com"
$label7.Width = 343
$label7.Height = 31
$label7.location = new-object system.drawing.point(42,218)
$label7.Font = "Microsoft Sans Serif,8"
$CNSWinUpdate.controls.Add($label7)

$acknowledge_chk = New-Object system.windows.Forms.CheckBox
$acknowledge_chk.Text = "I acknowledge that if my computer is offline it will patch the following day"
$acknowledge_chk.AutoSize = $true
$acknowledge_chk.Width = 95
$acknowledge_chk.Height = 20
$acknowledge_chk.Add_CheckStateChanged({
	if ($acknowledge_chk.Checked) {
		$OK.Visible = $true
	}
	else {
		$OK.Visible = $false
	}
})
$acknowledge_chk.location = new-object system.drawing.point(42,187)
$acknowledge_chk.Font = "Microsoft Sans Serif,10"
$CNSWinUpdate.controls.Add($acknowledge_chk)

[void]$CNSWinUpdate.ShowDialog()
$CNSWinUpdate.Dispose()