<?
// Klassendefinition
class OpnSenseStatechecker extends IPSModule {
    // Überschreibt die interne IPS_Create($id) Funktion
    public function Create() {
        // Diese Zeile nicht löschen.
        parent::Create();
        
        $this->RegisterPropertyString("Host","");
        $this->RegisterPropertyString("ApiKey","");
        $this->RegisterPropertyString("ApiSecret","");
        $this->RegisterTimer("Update", 10000, 'OSSC_CheckValues('.$this->InstanceID.');');
        if (!IPS_VariableProfileExists("CpuLoad"))
        {
            IPS_CreateVariableProfile("CpuLoad", 2);
            IPS_SetVariableProfileDigits ("CpuLoad", 1);
            IPS_SetVariableProfileIcon ("CpuLoad", "Speedo");
            IPS_SetVariableProfileText ("CpuLoad", "", " %");
            IPS_SetVariableProfileValues ("CpuLoad", 0, 100, 0);
        }

        if (!IPS_VariableProfileExists("Megabytes"))
        {
            IPS_CreateVariableProfile("Megabytes", 1);

            IPS_SetVariableProfileIcon ("Megabytes", "Database");
            IPS_SetVariableProfileText ("Megabytes", "", " MB");
            IPS_SetVariableProfileValues ("Megabytes", 0, 9999999, 0);
        }

        ///api/diagnostics/activity/getActivity/
        $this->RegisterVariableFloat("CpuLoadUsed", "CPU Load Used", "CpuLoad", 100);
        $this->RegisterVariableFloat("CpuLoadUnused", "CPU Load Unused", "CpuLoad", 110);
        $this->RegisterVariableFloat("CpuLoadUser", "CPU Load User", "CpuLoad", 120);
        $this->RegisterVariableFloat("CpuLoadNice", "CPU Load Nice", "CpuLoad", 130);
        $this->RegisterVariableFloat("CpuLoadSystem", "CPU Load System", "CpuLoad", 140);
        $this->RegisterVariableFloat("CpuLoadInterrupt", "CPU Load Interrupt", "CpuLoad", 150);

        $this->RegisterVariableInteger("MemoryActive", "Memory active", "Megabytes", 200);
        $this->RegisterVariableInteger("MemoryInactive", "Memory inactive", "Megabytes", 210);
        $this->RegisterVariableInteger("MemoryWired", "Memory wired", "Megabytes", 220);
        $this->RegisterVariableInteger("MemoryBuffer", "Memory buffer", "Megabytes", 230);
        $this->RegisterVariableInteger("MemoryFree", "Memory free", "Megabytes", 240);

        ///api/core/system/status/
        $this->RegisterVariableInteger("CrStatusCode", "Crashreporter Statuscode", "",300);
        $this->RegisterVariableString("CrMessage", "Crashreporter Message", "",310);
        $this->RegisterVariableString("CrLogLocation", "Crashreporter Loglocation", "",320);
        $this->RegisterVariableInteger("CrTimestamp", "Crashreporter Timestamp", "",330);
        $this->RegisterVariableString("CrStatus", "Crashreporter Status", "",340);

        $this->RegisterVariableInteger("FwStatusCode", "Firewall Statuscode", "",400);
        $this->RegisterVariableString("FwMessage", "Firewall Message", "",410);
        $this->RegisterVariableString("FwLogLocation", "Firewall Loglocation", "",420);
        $this->RegisterVariableInteger("FwTimestamp", "Firewall Timestamp", "",430);
        $this->RegisterVariableString("FwStatus", "Firewall Status", "",440);


    }

    // Überschreibt die intere IPS_ApplyChanges($id) Funktion
    public function ApplyChanges() {
        // Diese Zeile nicht löschen
        parent::ApplyChanges();

        $this->CheckValues();

    }

    public function CheckValues() {
            // Host mapping
            $host = $this->ReadPropertyString("Host");
            $api_key = $this->ReadPropertyString("ApiKey");
            $api_secret = $this->ReadPropertyString("ApiSecret");

            $url = "http://".$host."/api/diagnostics/activity/getActivity/";
            // Initialize cURL session
            $ch = curl_init();
            
            // Set cURL options
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Disable SSL verification (consider removing this in production)
            curl_setopt($ch, CURLOPT_SSLCERT, 'OPNsense.pem'); // Path to the certificate file
            
            // Set HTTP Basic Authentication
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($ch, CURLOPT_USERPWD, $api_key . ':' . $api_secret);
            
            // Execute the cURL request
            $response = curl_exec($ch);
            $response_data = json_decode($response, true);

            $inputString = $response_data["headers"][2];

            // Use regular expression to extract numeric values
            preg_match_all('/(\d+(?:\.\d+)?)\s*[GMK]?/', $inputString, $matches);
            
            // Assign values to individual variables
            list($CpuLoadUser, $CpuLoadNice, $CpuLoadSystem, $CpuLoadInterrupt, $CpuLoadUnused) = $matches[0];
            
            $CpuLoadUsed = 100 - $CpuLoadUnused;
            $this->SetValue("CpuLoadUsed", $CpuLoadUsed);
            $this->SetValue("CpuLoadUnused", $CpuLoadUnused);
            $this->SetValue("CpuLoadUser", $CpuLoadUser);
            $this->SetValue("CpuLoadNice", $CpuLoadNice);
            $this->SetValue("CpuLoadSystem", $CpuLoadSystem);
            $this->SetValue("CpuLoadInterrupt", $CpuLoadInterrupt);

            $inputString = $response_data["headers"][3];
            // Remove "M" from the input string
            $inputString = str_replace('M', '', $inputString);
            // Use regular expression to extract numeric values
            preg_match_all('/(\d+(?:\.\d+)?)\s*[GMK]?/', $inputString, $matches);

            // Assign values to individual variables
            list($MemActive, $MemInactive, $MemWired, $MemBuffer, $MemFree) = $matches[0];

            $this->SetValue("MemoryActive", $MemActive);
            $this->SetValue("MemoryInactive", $MemInactive);
            $this->SetValue("MemoryWired", $MemWired);
            $this->SetValue("MemoryBuffer", $MemBuffer);
            $this->SetValue("MemoryFree", $MemFree);

            $url = "http://".$host."/api/core/system/status/";
            curl_setopt($ch, CURLOPT_URL, $url);

            // Execute the cURL request
            $response = curl_exec($ch);
            $response_data = json_decode($response, true);

            $this->SetValue("CrStatusCode", $response_data["CrashReporter"]["statusCode"]);
            $this->SetValue("CrMessage", $response_data["CrashReporter"]["message"]);
            $this->SetValue("CrLogLocation", $response_data["CrashReporter"]["logLocation"]);
            $this->SetValue("CrTimestamp", $response_data["CrashReporter"]["timestamp"]);
            $this->SetValue("CrStatus", $response_data["CrashReporter"]["status"]);

            $this->SetValue("FwStatusCode", $response_data["Firewall"]["statusCode"]);
            $this->SetValue("FwMessage", $response_data["Firewall"]["message"]);
            $this->SetValue("FwLogLocation", $response_data["Firewall"]["logLocation"]);
            $this->SetValue("FwTimestamp", $response_data["Firewall"]["timestamp"]);
            $this->SetValue("FwStatus", $response_data["Firewall"]["status"]);



            //Close cURL session
            curl_close($ch);

    }
}
?>