#Config Variables
$TenantSiteURL =  "https://occasionallymade-admin.sharepoint.com/"
$CSVFilePath = "C:\Users\mhollier\OneDrive - Bastionpoint Technology LLC (1)\Documents\Swig\AllSitesData.csv"
 
#Connect to Tenant Admin Site
Connect-PnPOnline -Url $TenantSiteURL -Interactive
 
#Get All Site collections data and export to CSV
Get-PnPTenantSite -Detailed 


#Read more: https://www.sharepointdiary.com/2016/02/get-all-site-collections-in-sharepoint-online-using-powershell.html#ixzz8Fqz3oHWP