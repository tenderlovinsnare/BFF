

# Define the domain and IP address to respond with
$domain = "example.com"
$responseIP = "192.168.1.1"

# Create a UDP client to listen on port 53
$udpClient = New-Object System.Net.Sockets.UdpClient(53)
$endPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 53)

Write-Host "DNS Server running on port 53. Listening for queries..."

while ($true) {
    # Receive DNS request
    $request = $udpClient.Receive([ref]$endPoint)
    
    # Parse the query (assuming a simple `A` record request for $domain)
    $questionDomain = ""
    $index = 12  # DNS question starts at byte 12 in the packet

    # Extract the domain name from the query packet
    while ($request[$index] -ne 0) {
        $length = $request[$index]
        $index++
        $questionDomain += [System.Text.Encoding]::ASCII.GetString($request, $index, $length) + "."
        $index += $length
    }
    $questionDomain = $questionDomain.TrimEnd(".")

    # Check if the query matches the configured domain
    if ($questionDomain -eq $domain) {
        Write-Host "Received query for $domain. Responding with IP $responseIP."

        # Build a response packet based on the query ID and format
        $response = New-Object byte[] ($request.Length + 16)
        $request.CopyTo($response, 0)
        
        # Set DNS flags for response (standard query response, no error)
        $response[2] = 0x81
        $response[3] = 0x80

        # Set answer count to 1
        $response[6] = 0x00
        $response[7] = 0x01

        # Position the answer section immediately after the question
        $answerIndex = $index + 5
        $response[$answerIndex] = 0xC0
        $response[$answerIndex + 1] = 0x0C  # Pointer to the domain name in question
        $response[$answerIndex + 2] = 0x00  # Type: A record
        $response[$answerIndex + 3] = 0x01
        $response[$answerIndex + 4] = 0x00  # Class: IN
        $response[$answerIndex + 5] = 0x01
        $response[$answerIndex + 6] = 0x00  # TTL (32-bit, 60 seconds)
        $response[$answerIndex + 7] = 0x00
        $response[$answerIndex + 8] = 0x00
        $response[$answerIndex + 9] = 0x3C
        $response[$answerIndex + 10] = 0x00  # Data length
        $response[$answerIndex + 11] = 0x04

        # Insert the IP address (4 bytes) into the response
        $ipBytes = [System.Net.IPAddress]::Parse($responseIP).GetAddressBytes()
        $ipBytes.CopyTo($response, $answerIndex + 12)

        # Send the response
        $udpClient.Send($response, $response.Length, $endPoint)
    } else {
        Write-Host "Received query for unrecognized domain: $questionDomain"
    }
}



