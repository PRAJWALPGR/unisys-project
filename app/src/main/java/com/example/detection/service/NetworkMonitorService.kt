package com.example.detection.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import okhttp3.Interceptor
import okhttp3.Response
import java.io.BufferedReader
import java.io.FileReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class NetworkMonitorService(private val context: Context) {
    private val suspiciousIPs = ConcurrentHashMap<String, AtomicInteger>()
    private val blacklistedDomains = setOf(
        "malicious-domain.com",
        "suspicious-api.com",
        "fake-server.net"
    )
    
    // Cache for network state to prevent unnecessary updates
    private var lastNetworkState: NetworkState? = null
    
    // Cache for IP counts to reduce memory usage
    private val ipCountCache = ConcurrentHashMap<String, Int>()
    private val cacheTimeout = 5 * 60 * 1000 // 5 minutes
    private val lastCacheUpdate = ConcurrentHashMap<String, Long>()
    
    // Network statistics tracking
    private val uploadTraffic = AtomicLong(0)
    private val downloadTraffic = AtomicLong(0)
    private var activeNetworkType = "Unknown"
    private var vpnInUse = false
    private var proxyDetected = false
    private var lastIpAddresses = listOf<String>()
    private var lastDnsServers = listOf<String>()
    private var activeConnections = listOf<String>()

    // Settings controls
    private var enabled = true
    private var stealthModeEnabled = false

    /**
     * Enable or disable the network monitoring service.
     */
    fun setEnabled(enabled: Boolean) {
        this.enabled = enabled
        if (enabled) {
            startMonitoring()
        } else {
            stopMonitoring()
        }
    }

    /**
     * Enable or disable stealth mode for network monitoring.
     */
    fun setStealthModeEnabled(enabled: Boolean) {
        this.stealthModeEnabled = enabled
        // Apply stealth settings immediately
        configureMonitoring()
    }

    private fun configureMonitoring() {
        // Adjust monitoring behavior based on current settings
    }

    private fun startMonitoring() {
        if (!enabled) return
        
        // Implementation details for starting monitoring
    }

    private fun stopMonitoring() {
        // Implementation details for stopping monitoring
    }

    fun monitorNetworkChanges(): Flow<NetworkState> = callbackFlow {
        val connectivityManager = 
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val networkRequest = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (lastNetworkState != NetworkState.Available) {
                    lastNetworkState = NetworkState.Available
                    trySend(NetworkState.Available)
                }
                
                // Update network information when connection becomes available
                updateNetworkInfo(network)
            }

            override fun onLost(network: Network) {
                if (lastNetworkState != NetworkState.Lost) {
                    lastNetworkState = NetworkState.Lost
                    trySend(NetworkState.Lost)
                }
            }

            override fun onUnavailable() {
                if (lastNetworkState != NetworkState.Unavailable) {
                    lastNetworkState = NetworkState.Unavailable
                    trySend(NetworkState.Unavailable)
                }
            }
            
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Update network type when capabilities change
                updateNetworkType(capabilities)
                // Check for VPN
                vpnInUse = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        }

        connectivityManager.registerNetworkCallback(networkRequest, callback)

        awaitClose {
            connectivityManager.unregisterNetworkCallback(callback)
        }
    }.distinctUntilChanged() // Only emit when state actually changes
    
    /**
     * Update network information based on current active network
     */
    private fun updateNetworkInfo(network: Network) {
        try {
            // Get IP addresses
            lastIpAddresses = getLocalIpAddresses()
            
            // Get DNS servers
            lastDnsServers = getDnsServers()
            
            // Update active connections
            updateActiveConnections()
        } catch (e: Exception) {
            Log.e("NetworkMonitorService", "Error updating network info: ${e.message}")
        }
    }
    
    /**
     * Update network type based on network capabilities
     */
    private fun updateNetworkType(capabilities: NetworkCapabilities) {
        activeNetworkType = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile Data"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "Bluetooth"
            else -> "Unknown"
        }
    }
    
    /**
     * Get local IP addresses from network interfaces
     */
    private fun getLocalIpAddresses(): List<String> {
        val addresses = mutableListOf<String>()
        try {
            val networkInterfaces = NetworkInterface.getNetworkInterfaces()
            while (networkInterfaces.hasMoreElements()) {
                val networkInterface = networkInterfaces.nextElement()
                val inetAddresses = networkInterface.inetAddresses
                while (inetAddresses.hasMoreElements()) {
                    val address = inetAddresses.nextElement()
                    if (!address.isLoopbackAddress && address is Inet4Address) {
                        addresses.add(address.hostAddress ?: "Unknown")
                    }
                }
            }
            
            // If no addresses found, try to get from WifiManager
            if (addresses.isEmpty()) {
                val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                if (wifiManager != null) {
                    val wifiInfo = wifiManager.connectionInfo
                    val ipAddress = wifiInfo.ipAddress
                    if (ipAddress != 0) {
                        addresses.add(
                            String.format(
                                "%d.%d.%d.%d",
                                ipAddress and 0xff,
                                ipAddress shr 8 and 0xff,
                                ipAddress shr 16 and 0xff,
                                ipAddress shr 24 and 0xff
                            )
                        )
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("NetworkMonitorService", "Error getting IP addresses: ${e.message}")
        }
        
        return if (addresses.isEmpty()) listOf("Not available") else addresses
    }
    
    /**
     * Get DNS servers from system configuration
     */
    private fun getDnsServers(): List<String> {
        val dnsServers = mutableListOf<String>()
        try {
            // Prefer ConnectivityManager LinkProperties if possible (more accurate on Android)
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val lp = cm?.activeNetwork?.let { cm.getLinkProperties(it) }
            val linkDns = lp?.dnsServers?.mapNotNull { it.hostAddress }
            if (!linkDns.isNullOrEmpty()) {
                dnsServers.addAll(linkDns)
            }
            
            if (dnsServers.isEmpty()) {
                // Fallback to /etc/resolv.conf
                val reader = BufferedReader(FileReader("/etc/resolv.conf"))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line?.startsWith("nameserver") == true) {
                        val parts = line?.split("\\s+".toRegex())
                        if (parts != null && parts.size > 1) {
                            dnsServers.add(parts[1])
                        }
                    }
                }
                reader.close()
            }
        } catch (e: Exception) {
            Log.e("NetworkMonitorService", "Could not read DNS servers: ${e.message}")
        }
        
        if (dnsServers.isEmpty()) {
            // Provide informative defaults rather than mixing label+IP
            dnsServers.add("8.8.8.8")
            dnsServers.add("1.1.1.1")
        }
        
        return dnsServers
    }
    
    /**
     * Update active network connections
     */
    private fun updateActiveConnections() {
        val connections = mutableListOf<String>()
        try {
            // Prefer proc/net/tcp parsing to avoid shell dependency where possible
            val proc = listOf("/proc/net/tcp", "/proc/net/tcp6")
            var added = 0
            for (path in proc) {
                try {
                    java.io.File(path).forEachLine { line ->
                        if (added >= 8) return@forEachLine
                        if (line.contains(": 01")) { // 01 = ESTABLISHED
                            connections.add("Established connection")
                            added++
                        }
                    }
                } catch (_: Exception) { }
            }
            
            if (added == 0) {
                // Fallback to netstat if proc parse failed
                val process = Runtime.getRuntime().exec("netstat -tn")
                val reader = process.inputStream.bufferedReader()
                var line: String?
                var count = 0
                while (reader.readLine().also { line = it } != null && count < 5) {
                    if (line?.contains("ESTABLISHED") == true) {
                        connections.add("Established connection")
                        count++
                    }
                }
                process.destroy()
            }
        } catch (e: Exception) {
            Log.e("NetworkMonitorService", "Error getting active connections: ${e.message}")
        }
        
        activeConnections = if (connections.isEmpty()) listOf("No active connections") else connections
    }

    fun createNetworkInterceptor(): Interceptor {
        return object : Interceptor {
            override fun intercept(chain: Interceptor.Chain): Response {
                val request = chain.request()
                val host = request.url.host
                
                // Check if the domain is blacklisted
                if (blacklistedDomains.any { host.contains(it) }) {
                    throw SecurityException("Attempted connection to blacklisted domain: $host")
                }

                // Track IP addresses with atomic counter
                val ip = request.url.host
                suspiciousIPs.computeIfAbsent(ip) { AtomicInteger(0) }.incrementAndGet()

                // Estimate traffic (this is a very rough estimate for demonstration)
                val requestLength = request.toString().length.toLong()
                uploadTraffic.addAndGet(requestLength)
                
                val response = chain.proceed(request)
                
                // Estimate response size
                val responseLength = response.body?.contentLength() ?: 0L
                downloadTraffic.addAndGet(responseLength)
                
                return response
            }
        }
    }

    fun getSuspiciousIPCount(ip: String): Int {
        val currentTime = System.currentTimeMillis()
        val lastUpdate = lastCacheUpdate.getOrDefault(ip, 0L)
        
        // Return cached value if it's still valid
        if (currentTime - lastUpdate < cacheTimeout) {
            return ipCountCache.getOrDefault(ip, 0)
        }
        
        // Update cache with new value
        val count = suspiciousIPs.getOrDefault(ip, AtomicInteger(0)).get()
        ipCountCache[ip] = count
        lastCacheUpdate[ip] = currentTime
        
        return count
    }

    fun clearSuspiciousIPHistory() {
        suspiciousIPs.clear()
        ipCountCache.clear()
        lastCacheUpdate.clear()
    }
    
    /**
     * Get current network statistics
     */
    fun getNetworkStats(): NetworkStats {
        return NetworkStats(
            uploadTraffic = uploadTraffic.get(),
            downloadTraffic = downloadTraffic.get(),
            activeNetworkType = activeNetworkType,
            ipAddresses = lastIpAddresses,
            dnsServers = lastDnsServers,
            activeConnections = activeConnections,
            vpnInUse = vpnInUse,
            proxyDetected = proxyDetected
        )
    }
    
    /**
     * Reset traffic counters
     */
    fun resetTrafficCounters() {
        uploadTraffic.set(0)
        downloadTraffic.set(0)
    }

    sealed class NetworkState {
        object Available : NetworkState()
        object Lost : NetworkState()
        object Unavailable : NetworkState()
    }
    
    /**
     * Data class for network statistics
     */
    data class NetworkStats(
        val uploadTraffic: Long,
        val downloadTraffic: Long,
        val activeNetworkType: String,
        val ipAddresses: List<String>,
        val dnsServers: List<String>,
        val activeConnections: List<String>,
        val vpnInUse: Boolean,
        val proxyDetected: Boolean
    )

    /**
     * Data class for network activity information
     */
    data class NetworkActivity(
        val ipAddress: String,
        val port: Int,
        val protocol: String,
        val timestamp: Long
    )

    /**
     * Process network activity
     */
    private fun processNetworkActivity(network: Network?, activity: NetworkActivity) {
        // Implementation here
    }
} 