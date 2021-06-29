Set-ExecutionPolicy Bypass
$FileName1 = "C:\Freshly\ServFresh.Zip"
$FileName2 = "C:\Freshly\ServFresh-main"
    If ((test-path $FileName1) -and (test-path $FileName2))
    {
      Remove-Item $FileName1 -Force
      Remove-Item $FileName2 -Force    
    }

function downloadbuilder {

     Invoke-WebRequest -Uri "https://github.com/vvsonic/ServFresh/archive/refs/heads/main.zip" -OutFile "C:\Freshly\ServFresh.zip"
     Expand-Archive C:\Freshly\ServFresh.zip -DestinationPath C:\Freshly\
}
downloadbuilder