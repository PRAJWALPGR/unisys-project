package com.example.detection.ui

import android.os.Bundle
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.detection.service.CloneDetectionService
import com.example.detection.service.NetworkMonitorService
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import com.example.detection.service.CloneDetectionService.ScanType
import com.example.detection.service.BlockchainScanService
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Gesture
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Settings
import androidx.compose.foundation.background
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import com.example.detection.service.NeuralFingerprintService
import androidx.compose.material.icons.filled.RotateRight
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material.icons.filled.RemoveCircle
import com.example.detection.service.NetworkMirrorReflectionService
import com.example.detection.service.TrapInteractionRecorder
import androidx.compose.runtime.livedata.observeAsState
import com.example.detection.service.CloneDetectionService.ThreatLevel
import com.example.detection.service.DeepScanService
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.NetworkCell
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.SignalWifiStatusbarConnectedNoInternet4
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.AddAlert
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.List
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.unit.Dp
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.DrawScope
import com.example.detection.ui.components.*
import com.example.detection.ui.theme.*
import com.example.detection.honeypot.emotiontrap.EmotionalDeceptionManager
import com.example.detection.ui.screens.SettingsScreen
import com.example.detection.data.repositories.SettingsRepository
import com.example.detection.service.SettingsConnector
import androidx.lifecycle.lifecycleScope
import androidx.compose.material.icons.filled.Help
import androidx.compose.material.icons.automirrored.filled.Help
import androidx.compose.material3.HorizontalDivider
import android.widget.Toast
import androidx.compose.ui.platform.LocalContext

// Use Material3's HorizontalDivider directly
// No need for a custom wrapper

@Composable
fun LinearProgressIndicator(
    progress: Float,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
    trackColor: Color = MaterialTheme.colorScheme.surfaceVariant
) {
    androidx.compose.material3.LinearProgressIndicator(
        progress = { progress },
        modifier = modifier,
        color = color,
        trackColor = trackColor
    )
}

@Composable
fun LinearProgressIndicator(
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
    trackColor: Color = MaterialTheme.colorScheme.surfaceVariant
) {
    androidx.compose.material3.LinearProgressIndicator(
        modifier = modifier,
        color = color,
        trackColor = trackColor
    )
}

// Add this enum class to replace AutoMirrored
enum class AutoMirrored {
    Filled;
    
    companion object {
        val Help = Icons.AutoMirrored.Filled.Help
    }
}

enum class Screen(
    val title: String,
    val icon: ImageVector,
    val selectedIcon: ImageVector
) {
    Scanner("Scanner", Icons.Default.Security, Icons.Default.Security),
    Network("Network", Icons.Default.NetworkCheck, Icons.Default.NetworkCheck),
    // NeuralFingerprint("Neural Fingerprint", Icons.Default.Fingerprint, Icons.Default.Fingerprint),
    Honeypot("Honeypot", Icons.Default.BugReport, Icons.Default.BugReport),
    NeuralFingerprint("Neural Fingerprint", Icons.Default.Fingerprint, Icons.Default.Fingerprint),
    Settings("Settings", Icons.Default.Settings, Icons.Default.Settings)
}

@OptIn(ExperimentalMaterial3Api::class)
class MainActivity : ComponentActivity() {
    private lateinit var cloneDetectionService: CloneDetectionService
    private lateinit var networkMonitorService: NetworkMonitorService
    private lateinit var neuralFingerprintService: NeuralFingerprintService
    private lateinit var networkMirrorReflectionService: NetworkMirrorReflectionService
    private lateinit var trapInteractionRecorder: TrapInteractionRecorder
    private lateinit var deepScanService: DeepScanService
    private lateinit var emotionalDeceptionManager: EmotionalDeceptionManager
    private lateinit var settingsRepository: SettingsRepository
    private lateinit var blockchainScanService: BlockchainScanService
    private lateinit var settingsConnector: SettingsConnector

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        trapInteractionRecorder = TrapInteractionRecorder(this)
        cloneDetectionService = CloneDetectionService(this)
        networkMonitorService = NetworkMonitorService(this)
        neuralFingerprintService = NeuralFingerprintService(this)
        networkMirrorReflectionService = NetworkMirrorReflectionService(this, trapInteractionRecorder)
        deepScanService = DeepScanService(this)
        blockchainScanService = BlockchainScanService(this)
        
        // Initialize the Emotional Deception Environment for honeypot
        emotionalDeceptionManager = EmotionalDeceptionManager(this, trapInteractionRecorder)
        emotionalDeceptionManager.initialize()
        
        // Initialize the Mirror Network Reflection Test system
        networkMirrorReflectionService.initialize()
        
        // Initialize the Settings Repository
        settingsRepository = SettingsRepository(this)
        
        // Initialize the Settings Connector to connect settings changes to services
        settingsConnector = SettingsConnector(
            context = this,
            lifecycleScope = lifecycleScope,
            cloneDetectionService = cloneDetectionService,
            networkMonitorService = networkMonitorService,
            neuralFingerprintService = neuralFingerprintService,
            networkMirrorReflectionService = networkMirrorReflectionService,
            deepScanService = deepScanService,
            blockchainScanService = blockchainScanService,
            emotionalDeceptionManager = emotionalDeceptionManager
        )
        
        // Apply initial settings and start observing changes
        lifecycleScope.launch {
            settingsConnector.applyInitialSettings()
            settingsConnector.initialize()
        }
        
        // Check for usage stats permission needed for network traffic monitoring
        checkUsageStatsPermission()

        setContent {
            MaterialTheme {
                CloneDetectionApp(
                    cloneDetectionService = cloneDetectionService,
                    networkMonitorService = networkMonitorService,
                    neuralFingerprintService = neuralFingerprintService,
                    networkMirrorReflectionService = networkMirrorReflectionService,
                    deepScanService = deepScanService,
                    emotionalDeceptionManager = emotionalDeceptionManager
                )
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        neuralFingerprintService.cleanup()
        emotionalDeceptionManager.cleanup()
    }

    /**
     * Check if the app has permission to access usage statistics
     * Used for network traffic monitoring
     */
    private fun checkUsageStatsPermission() {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                packageName
            )
        }
        
        if (mode != AppOpsManager.MODE_ALLOWED) {
            // Show dialog requesting permission
            // Permission must be granted via Settings > Apps > Special app access > Usage access
            android.app.AlertDialog.Builder(this)
                .setTitle("Permission Required")
                .setMessage("This app needs Usage Access permission to monitor network traffic. Please enable this in Settings.")
                .setPositiveButton("Settings") { _, _ ->
                    val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                    startActivity(intent)
                }
                .setNegativeButton("Later", null)
                .show()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CloneDetectionApp(
    cloneDetectionService: CloneDetectionService,
    networkMonitorService: NetworkMonitorService,
    neuralFingerprintService: NeuralFingerprintService,
    networkMirrorReflectionService: NetworkMirrorReflectionService,
    deepScanService: DeepScanService,
    emotionalDeceptionManager: EmotionalDeceptionManager
) {
    var selectedScreen by remember { mutableStateOf(Screen.Scanner) }
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    // Dialog states
    var showHowItWorksDialog by remember { mutableStateOf(false) }
    var showSecurityFeaturesDialog by remember { mutableStateOf(false) }
    var showCreateHoneypotDialog by remember { mutableStateOf(false) }
    var showMonitorTrapsDialog by remember { mutableStateOf(false) }
    var showActivityLogDialog by remember { mutableStateOf(false) }

    MaterialTheme {
        ModalNavigationDrawer(
            drawerState = drawerState,
            drawerContent = {
                ModalDrawerSheet {
                    Spacer(modifier = Modifier.height(16.dp))
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            modifier = Modifier.size(80.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Clone Detection",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            "Security Scanner",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))

                    // Honeypot Features Section
                    Text(
                        "Honeypot Features",
                        modifier = Modifier.padding(horizontal = 16.dp),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.Default.AddAlert, contentDescription = null) },
                        label = { Text("Create Honeypot") },
                        selected = false,
                        onClick = { 
                            scope.launch {
                                drawerState.close()
                                showCreateHoneypotDialog = true
                            }
                        }
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.Default.MonitorHeart, contentDescription = null) },
                        label = { Text("Monitor Traps") },
                        selected = false,
                        onClick = { 
                            scope.launch {
                                drawerState.close()
                                showMonitorTrapsDialog = true
                            }
                        }
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.Default.History, contentDescription = null) },
                        label = { Text("Activity Log") },
                        selected = false,
                        onClick = { 
                            scope.launch {
                                drawerState.close()
                                showActivityLogDialog = true
                            }
                        }
                    )

                    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))

                    // About Section
                    Text(
                        "About",
                        modifier = Modifier.padding(horizontal = 16.dp),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.Default.Info, contentDescription = null) },
                        label = { Text("How It Works") },
                        selected = false,
                        onClick = { 
                            scope.launch {
                                drawerState.close()
                                showHowItWorksDialog = true
                            }
                        }
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.Default.Shield, contentDescription = null) },
                        label = { Text("Security Features") },
                        selected = false,
                        onClick = { 
                            scope.launch {
                                drawerState.close()
                                showSecurityFeaturesDialog = true
                            }
                        }
                    )
                    NavigationDrawerItem(
                        icon = { Icon(Icons.AutoMirrored.Filled.Help, contentDescription = null) },
                        label = { Text("Help & Support") },
                        selected = false,
                        onClick = { /* TODO */ }
                    )
                }
            }
        ) {
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = { Text(selectedScreen.title) },
                        navigationIcon = {
                            IconButton(onClick = { 
                                scope.launch { drawerState.open() }
                            }) {
                                Icon(Icons.Default.Menu, contentDescription = "Menu")
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    )
                },
                bottomBar = {
                    NavigationBar {
                        Screen.values().forEach { screen ->
                            NavigationBarItem(
                                icon = {
                                    Icon(
                                        imageVector = if (selectedScreen == screen) {
                                            screen.selectedIcon
                                        } else {
                                            screen.icon
                                        },
                                        contentDescription = screen.title
                                    )
                                },
                                label = { Text(screen.title) },
                                selected = selectedScreen == screen,
                                onClick = { selectedScreen = screen }
                            )
                        }
                    }
                }
            ) { innerPadding ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    when (selectedScreen) {
                        Screen.Scanner -> ScannerScreen(
                            cloneDetectionService = cloneDetectionService,
                            networkMonitorService = networkMonitorService,
                            neuralFingerprintService = neuralFingerprintService
                        )
                        Screen.Network -> NetworkScreen(
                            networkMonitorService = networkMonitorService,
                            networkMirrorReflectionService = networkMirrorReflectionService
                        )
                        Screen.Honeypot -> HoneypotScreen(
                            cloneDetectionService = cloneDetectionService,
                            emotionalDeceptionManager = emotionalDeceptionManager
                        )
                        Screen.NeuralFingerprint -> NeuralFingerprintScreen(
                            neuralFingerprintService = neuralFingerprintService
                        )
                        Screen.Settings -> SettingsScreen()
                    }

                    // Show dialogs based on state
                    if (showCreateHoneypotDialog) {
                        var trapName by remember { mutableStateOf("") }
                        var selectedTrapType by remember { mutableStateOf(CloneDetectionService.TrapType.NETWORK) }
                        var trapTarget by remember { mutableStateOf("") }
                        var selectedAlertLevel by remember { mutableStateOf(CloneDetectionService.AlertLevel.MEDIUM) }
                        var description by remember { mutableStateOf("") }
                        
                        AlertDialog(
                            onDismissRequest = { showCreateHoneypotDialog = false },
                            title = { Text("Create Honeypot") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Configure Honeypot Settings:", fontWeight = FontWeight.Bold)
                                    
                                    OutlinedTextField(
                                        value = trapName,
                                        onValueChange = { trapName = it },
                                        label = { Text("Trap Name") },
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    
                                    Text("Trap Type:", fontWeight = FontWeight.Medium)
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        FilterChip(
                                            selected = selectedTrapType == CloneDetectionService.TrapType.NETWORK,
                                            onClick = { selectedTrapType = CloneDetectionService.TrapType.NETWORK },
                                            label = { Text("Network") }
                                        )
                                        FilterChip(
                                            selected = selectedTrapType == CloneDetectionService.TrapType.FILE,
                                            onClick = { selectedTrapType = CloneDetectionService.TrapType.FILE },
                                            label = { Text("File") }
                                        )
                                        FilterChip(
                                            selected = selectedTrapType == CloneDetectionService.TrapType.PROCESS,
                                            onClick = { selectedTrapType = CloneDetectionService.TrapType.PROCESS },
                                            label = { Text("Process") }
                                        )
                                    }
                                    
                                    OutlinedTextField(
                                        value = trapTarget,
                                        onValueChange = { trapTarget = it },
                                        label = { Text("Target (Port/Path/Process)") },
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    
                                    Text("Alert Level:", fontWeight = FontWeight.Medium)
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        FilterChip(
                                            selected = selectedAlertLevel == CloneDetectionService.AlertLevel.LOW,
                                            onClick = { selectedAlertLevel = CloneDetectionService.AlertLevel.LOW },
                                            label = { Text("Low") }
                                        )
                                        FilterChip(
                                            selected = selectedAlertLevel == CloneDetectionService.AlertLevel.MEDIUM,
                                            onClick = { selectedAlertLevel = CloneDetectionService.AlertLevel.MEDIUM },
                                            label = { Text("Medium") }
                                        )
                                        FilterChip(
                                            selected = selectedAlertLevel == CloneDetectionService.AlertLevel.HIGH,
                                            onClick = { selectedAlertLevel = CloneDetectionService.AlertLevel.HIGH },
                                            label = { Text("High") }
                                        )
                                    }
                                    
                                    OutlinedTextField(
                                        value = description,
                                        onValueChange = { description = it },
                                        label = { Text("Description (Optional)") },
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                            },
                            confirmButton = {
                                Button(
                                    onClick = {
                                        if (trapName.isNotBlank() && trapTarget.isNotBlank()) {
                                            cloneDetectionService.addTrap(
                                                trapName,
                                                selectedTrapType,
                                                trapTarget,
                                                selectedAlertLevel,
                                                description.ifBlank { "Monitoring ${selectedTrapType.name.lowercase()} target: $trapTarget" }
                                            )
                                            showCreateHoneypotDialog = false
                                        }
                                    },
                                    enabled = trapName.isNotBlank() && trapTarget.isNotBlank()
                                ) {
                                    Text("Create")
                                }
                            },
                            dismissButton = {
                                TextButton(onClick = { showCreateHoneypotDialog = false }) {
                                    Text("Cancel")
                                }
                            }
                        )
                    }

                    if (showMonitorTrapsDialog) {
                        val activeTraps = remember { cloneDetectionService.getActiveTraps() }
                        
                        AlertDialog(
                            onDismissRequest = { showMonitorTrapsDialog = false },
                            title = { Text("Active Honeypot Traps") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (activeTraps.isEmpty()) {
                                        Text(
                                            "No active traps found. Create a trap to start monitoring.",
                                            style = MaterialTheme.typography.bodyMedium,
                                            modifier = Modifier.padding(vertical = 16.dp),
                                            textAlign = TextAlign.Center
                                        )
                                    } else {
                                        activeTraps.forEach { trap ->
                                            val icon = when (trap.type) {
                                                CloneDetectionService.TrapType.NETWORK -> Icons.Default.NetworkCheck
                                                CloneDetectionService.TrapType.FILE -> Icons.Default.Folder
                                                CloneDetectionService.TrapType.PROCESS -> Icons.Default.Memory
                                            }
                                            
                                            ListItem(
                                                headlineContent = { Text(trap.name) },
                                                supportingContent = { Text("Monitoring: ${trap.target}") },
                                                leadingContent = { 
                                                    Icon(
                                                        icon,
                                                        contentDescription = null,
                                                        tint = MaterialTheme.colorScheme.primary
                                                    )
                                                },
                                                trailingContent = {
                                                    Icon(
                                                        Icons.Default.Circle,
                                                        contentDescription = null,
                                                        tint = if (trap.isActive) Color.Green else Color.Gray
                                                    )
                                                }
                                            )
                                        }
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { showMonitorTrapsDialog = false }) {
                                    Text("Close")
                                }
                            }
                        )
                    }

                    if (showActivityLogDialog) {
                        val trapActivities = remember { cloneDetectionService.getTrapActivities() }
                        
                        AlertDialog(
                            onDismissRequest = { showActivityLogDialog = false },
                            title = { Text("Honeypot Activity Log") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (trapActivities.isEmpty()) {
                                        Text(
                                            "No activity recorded yet.",
                                            style = MaterialTheme.typography.bodyMedium,
                                            textAlign = TextAlign.Center,
                                            modifier = Modifier.padding(vertical = 16.dp)
                                        )
                                    } else {
                                        trapActivities.take(10).forEach { activity ->
                                            val icon = when {
                                                activity.severity == "HIGH" -> Icons.Default.Warning
                                                activity.actionType == "ACCESSED" -> Icons.Default.Info
                                                else -> Icons.Default.BugReport
                                            }
                                            
                                            val timeAgo = getTimeAgo(activity.timestamp)
                                            
                                            ListItem(
                                                headlineContent = { Text("${activity.actionType}: ${activity.trapName}") },
                                                supportingContent = { Text("${activity.details} - $timeAgo") },
                                                leadingContent = { 
                                                    Icon(
                                                        icon,
                                                        contentDescription = null,
                                                        tint = when (activity.severity) {
                                                            "HIGH" -> MaterialTheme.colorScheme.error
                                                            "MEDIUM" -> MaterialTheme.colorScheme.tertiary
                                                            else -> MaterialTheme.colorScheme.primary
                                                        }
                                                    )
                                                }
                                            )
                                        }
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { showActivityLogDialog = false }) {
                                    Text("Close")
                                }
                            }
                        )
                    }

                    if (showHowItWorksDialog) {
                        AlertDialog(
                            onDismissRequest = { showHowItWorksDialog = false },
                            title = { Text("How It Works") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Our app uses advanced security techniques to detect and prevent app cloning:")
                                    
                                    Text("1. Root Detection", fontWeight = FontWeight.Bold)
                                    Text("Checks for unauthorized root access and system modifications")
                                    
                                    Text("2. Signature Verification", fontWeight = FontWeight.Bold)
                                    Text("Ensures app hasn't been tampered with or modified")
                                    
                                    Text("3. Honeypot System", fontWeight = FontWeight.Bold)
                                    Text("Sets up traps to detect and monitor suspicious activities")
                                    
                                    Text("4. Real-time Monitoring", fontWeight = FontWeight.Bold)
                                    Text("Continuously monitors for suspicious behaviors and clone attempts")
                                    
                                    Text("5. Network Security", fontWeight = FontWeight.Bold)
                                    Text("Monitors network activities and prevents unauthorized access")
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { showHowItWorksDialog = false }) {
                                    Text("Close")
                                }
                            }
                        )
                    }

                    if (showSecurityFeaturesDialog) {
                        AlertDialog(
                            onDismissRequest = { showSecurityFeaturesDialog = false },
                            title = { Text("Security Features") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Key Security Features:", fontWeight = FontWeight.Bold)
                                    
                                    Text("• Root Detection")
                                    Text("• App Signature Verification")
                                    Text("• System Property Monitoring")
                                    Text("• Installation Source Validation")
                                    Text("• Device Identity Verification")
                                    Text("• Honeypot Traps")
                                    Text("• Network Traffic Monitoring")
                                    Text("• Debug Mode Detection")
                                    Text("• Emulator Detection")
                                    Text("• Multiple Instance Prevention")
                                    
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("Technologies Used:", fontWeight = FontWeight.Bold)
                                    Text("• RootBeer for root detection")
                                    Text("• SSL/TLS for secure communication")
                                    Text("• SHA-256 for signature verification")
                                    Text("• Android Security Library")
                                    Text("• Material 3 Design System")
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = { showSecurityFeaturesDialog = false }) {
                                    Text("Close")
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun ScannerScreen(
    cloneDetectionService: CloneDetectionService,
    networkMonitorService: NetworkMonitorService,
    neuralFingerprintService: NeuralFingerprintService,
    modifier: Modifier = Modifier
) {
    var detectionResult by remember { mutableStateOf<CloneDetectionService.DetectionResult?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }
    var selectedScanType by remember { mutableStateOf(ScanType.Quick) }
    var showCloneAppDetails by remember { mutableStateOf(false) }
    var showRootStatusDetails by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Logo and Description Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = "Clone Detection Logo",
                    modifier = Modifier.size(64.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Text(
                    "Clone Detection Scanner",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Detect and prevent app cloning attempts",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                )
            }
        }

        // Scan Options Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Scan Options",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    FilterChip(
                        selected = selectedScanType == ScanType.Quick,
                        onClick = { selectedScanType = ScanType.Quick },
                        label = { Text("Quick Scan") },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Speed,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    )
                    
                    FilterChip(
                        selected = selectedScanType == ScanType.Deep,
                        onClick = { selectedScanType = ScanType.Deep },
                        label = { Text("Deep Scan") },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Search,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    )
                    
                    FilterChip(
                        selected = selectedScanType == ScanType.Blockchain,
                        onClick = { selectedScanType = ScanType.Blockchain },
                        label = { Text("Blockchain Scan") },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Security,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    )
                    
                    FilterChip(
                        selected = selectedScanType == ScanType.Custom,
                        onClick = { selectedScanType = ScanType.Custom },
                        label = { Text("Custom") },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Settings,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    )
                }

                if (selectedScanType == ScanType.Custom) {
                    Column(
                        modifier = Modifier.padding(top = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Root Detection")
                            Switch(
                                checked = true,
                                onCheckedChange = { }
                            )
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Signature Verification")
                            Switch(
                                checked = true,
                                onCheckedChange = { }
                            )
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("System Properties")
                            Switch(
                                checked = true,
                                onCheckedChange = { }
                            )
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Installation Source")
                            Switch(
                                checked = true,
                                onCheckedChange = { }
                            )
                        }
                    }
                }
            }
        }

        // Scan Progress Card (visible during scan)
        AnimatedVisibility(
            visible = isScanning,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        "Scanning in Progress",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    LinearProgressIndicator(
                        progress = { scanProgress },
                        modifier = Modifier.fillMaxWidth(),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.primaryContainer,
                        strokeCap = StrokeCap.Round
                    )
                    
                    Text(
                        when {
                            scanProgress < 0.3f -> "Checking root status..."
                            scanProgress < 0.5f -> "Verifying app signature..."
                            scanProgress < 0.7f -> "Analyzing system properties..."
                            scanProgress < 0.9f -> "Validating installation source..."
                            else -> "Finalizing scan results..."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }
        }

        // Scan Button
        // Cooldown state to debounce scans
        var lastScanTimestamp by remember { mutableStateOf(0L) }
        val scanCooldownMs = 5000L
        val context = LocalContext.current

        Button(
            onClick = {
                val now = System.currentTimeMillis()
                if (isScanning) return@Button
                if (now - lastScanTimestamp < scanCooldownMs) {
                    Toast.makeText(context, "Please wait a moment before scanning again.", Toast.LENGTH_SHORT).show()
                    return@Button
                }
                isScanning = true
                scanProgress = 0f
                scope.launch {
                    cloneDetectionService.detectClone(selectedScanType).collect { result ->
                        scanProgress = (result.scanProgress / 100f).coerceIn(0f, 1f)
                        detectionResult = result
                        if (result.scanProgress >= 100) {
                            isScanning = false
                            lastScanTimestamp = System.currentTimeMillis()
                        }
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isScanning,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary
            )
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(vertical = 4.dp)
            ) {
                if (isScanning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                } else {
                    Icon(
                        imageVector = Icons.Default.Search,
                        contentDescription = "Scan"
                    )
                }
                Text(if (isScanning) "Scanning..." else "Start ${selectedScanType.name} Scan")
            }
        }

        // Results Card
        detectionResult?.let { result ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (result.isCloneDetected)
                        MaterialTheme.colorScheme.errorContainer
                    else
                        MaterialTheme.colorScheme.tertiaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Scan Results",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Icon(
                            imageVector = if (result.isCloneDetected) 
                                Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = if (result.isCloneDetected) 
                                MaterialTheme.colorScheme.error 
                            else 
                                MaterialTheme.colorScheme.tertiary
                        )
                    }
                    
                    Text(
                        if (result.isCloneDetected)
                            "⚠️ Security issues detected!"
                        else
                            "✅ No security issues found.",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                    
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                    
                    // Basic Security Checks
                    Text(
                        "Basic Security Checks",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                    DetectionResultItem(
                        "Root Status",
                        !result.isRooted,
                            Icons.Default.Security,
                            modifier = Modifier.weight(1f),
                            details = if (result.isRooted) "Device is rooted" else "Device is not rooted"
                        )
                        
                        if (result.isRooted) {
                            IconButton(onClick = { showRootStatusDetails = true }) {
                                Icon(
                                    imageVector = Icons.Default.Info,
                                    contentDescription = "Details",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                    
                    DetectionResultItem(
                        "App Signature",
                        result.hasValidSignature,
                        Icons.Default.VerifiedUser
                    )
                    
                    DetectionResultItem(
                        "System Properties",
                        !result.hasSuspiciousProps,
                        Icons.Default.Settings
                    )
                    
                    DetectionResultItem(
                        "Installation Source",
                        result.hasValidInstaller,
                        Icons.Default.Store
                    )
                    
                    DetectionResultItem(
                        "Device Identifiers",
                        result.hasConsistentIds,
                        Icons.Default.Phonelink
                    )

                    // Malicious Apps Section (if found)
                    if (result.maliciousApps.isNotEmpty()) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "Suspicious Applications (${result.maliciousApps.size})",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold
                            )
                            
                            IconButton(onClick = { showCloneAppDetails = true }) {
                                Icon(
                                    imageVector = Icons.Default.MoreVert,
                                    contentDescription = "Show details",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                        
                        Text(
                            "Suspicious apps detected that may be clones or fakes",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                        
                        Column(
                            modifier = Modifier.padding(vertical = 8.dp)
                        ) {
                            result.maliciousApps.take(3).forEach { app ->
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    colors = CardDefaults.cardColors(
                                        containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
                                    )
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Warning,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.error,
                                            modifier = Modifier.size(24.dp)
                                        )
                                        Column(
                                            modifier = Modifier
                                                .weight(1f)
                                                .padding(start = 12.dp)
                                        ) {
                                            Text(
                                                app.appName,
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                app.packageName,
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                            Text(
                                                "Threat Level: ${app.threatLevel}",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = when (app.threatLevel) {
                                                    ThreatLevel.CRITICAL -> MaterialTheme.colorScheme.error
                                                    ThreatLevel.HIGH -> Color(0xFFFF6D00)
                                                    ThreatLevel.MEDIUM -> Color(0xFFFFB300)
                                                    else -> Color(0xFF689F38)
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                            
                            if (result.maliciousApps.size > 3) {
                                Text(
                                    "... and ${result.maliciousApps.size - 3} more suspicious apps",
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp)
                                )
                            }
                        }
                    }

                    // Deep Scan Results (if available)
                    if (selectedScanType == ScanType.Deep) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        
                        Text(
                            "Advanced Security Analysis",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        
                        // AI-Powered Anomaly Detection
                            DetectionResultItem(
                            "AI Anomaly Detection",
                            !result.hasAnomalies,
                            Icons.Default.Psychology,
                            details = if (result.hasAnomalies) 
                                "Detected: ${result.anomalyDetails.joinToString(", ")}"
                            else 
                                "No anomalies detected in system behavior"
                        )
                        
                        // Firmware Integrity
                            DetectionResultItem(
                                "Firmware Integrity",
                            !result.firmwareTampered,
                            Icons.Default.Security,
                            details = result.firmwareStatus
                            )
                        
                        // Hidden Apps Detection
                            DetectionResultItem(
                            "Hidden & Cloned Apps",
                            !result.hasHiddenApps,
                            Icons.Default.Apps,
                            details = if (result.hasHiddenApps)
                                "Found: ${result.hiddenAppsList.joinToString(", ")}"
                            else
                                "No hidden or cloned apps detected"
                        )
                        
                        // Process Monitoring
                        DetectionResultItem(
                            "Process Analysis",
                            !result.hasAbnormalProcesses,
                            Icons.Default.Memory,
                            details = result.processAnalysisDetails
                        )
                        
                        // Certificate Validation
                            DetectionResultItem(
                                "Certificate Chain",
                            !result.hasCertificateIssues,
                            Icons.Default.Lock,
                            details = result.certificateValidationDetails
                            )
                        
                        // Cryptographic Analysis
                            DetectionResultItem(
                                "Cryptographic Security",
                            !result.hasCryptoWeaknesses,
                            Icons.Default.Key,
                            details = result.cryptoAnalysisDetails
                            )
                        
                        // Hooking Detection
                            DetectionResultItem(
                            "Hooking Framework Detection",
                            !result.hasHookingFrameworks,
                            Icons.Default.Code,
                            details = if (result.hasHookingFrameworks)
                                "Detected: ${result.detectedFrameworks.joinToString(", ")}"
                            else
                                "No hooking frameworks detected"
                        )
                        
                        // Network Analysis
                            DetectionResultItem(
                                "Network Security",
                            !result.hasSuspiciousNetwork,
                            Icons.Default.NetworkCheck,
                            details = result.networkAnalysisDetails,
                            expandedContent = {
                                Column(modifier = Modifier.padding(start = 16.dp)) {
                                    // Network type and traffic information
                                    Text(
                                        "Network: ${result.activeNetworkType}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Bold
                                    )
                                    
                                    // Traffic information
                                    val downloadMB = result.downloadTraffic / (1024f * 1024f)
                                    val uploadMB = result.uploadTraffic / (1024f * 1024f)
                                    
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column {
                                            Text(
                                                "Download Traffic:",
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                String.format("%.2f MB", downloadMB),
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                        
                                        Column {
                                            Text(
                                                "Upload Traffic:",
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                String.format("%.2f MB", uploadMB),
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                    }
                                    
                                    // Suspicious connections warnings
                                    if (result.suspiciousConnections.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            "⚠️ Suspicious Connections Detected:",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                        
                                        result.suspiciousConnections.forEach { connection ->
                                            Card(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .padding(vertical = 4.dp),
                                                colors = CardDefaults.cardColors(
                                                    containerColor = when(connection.severity) {
                                                        DeepScanService.SeverityLevel.LOW -> MaterialTheme.colorScheme.surfaceVariant
                                                        DeepScanService.SeverityLevel.MEDIUM -> Color(0xFFFFF9C4) // Light yellow
                                                        DeepScanService.SeverityLevel.HIGH -> Color(0xFFFFCCBC) // Light orange
                                                        DeepScanService.SeverityLevel.CRITICAL -> Color(0xFFFFCDD2) // Light red
                                                    }
                                                )
                                            ) {
                                                Column(modifier = Modifier.padding(8.dp)) {
                                                    Text(
                                                        "${connection.protocol}: ${connection.ipAddress}" + 
                                                        if (connection.port > 0) ":${connection.port}" else "",
                                                        style = MaterialTheme.typography.bodyMedium,
                                                        fontWeight = FontWeight.Bold
                                                    )
                                                    Text(
                                                        connection.reason,
                                                        style = MaterialTheme.typography.bodySmall
                                                    )
                                                    Text(
                                                        "Severity: ${connection.severity}",
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = when(connection.severity) {
                                                            DeepScanService.SeverityLevel.LOW -> MaterialTheme.colorScheme.onSurface
                                                            DeepScanService.SeverityLevel.MEDIUM -> Color(0xFFFF9800) // Orange
                                                            DeepScanService.SeverityLevel.HIGH -> Color(0xFFF44336) // Red
                                                            DeepScanService.SeverityLevel.CRITICAL -> Color(0xFFD50000) // Dark Red
                                                        }
                                                    )
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Display IP Addresses
                                    if (result.networkIpAddresses.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            "IP Addresses:",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Bold
                                        )
                                        result.networkIpAddresses.forEach { ip ->
                                            Text(
                                                "• $ip",
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                    }
                                    
                                    // Display DNS servers
                                    if (result.networkDnsServers.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            "DNS Servers:",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Bold
                                        )
                                        result.networkDnsServers.forEach { dns ->
                                            Text(
                                                "• $dns",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = if (dns.startsWith("8.8.") || 
                                                            dns.startsWith("1.1.1.") || 
                                                            dns.startsWith("9.9.9.") ||
                                                            dns.startsWith("208.67.") ||
                                                            dns.startsWith("127.") ||
                                                            dns.startsWith("192.168.") ||
                                                            dns.startsWith("10."))
                                                            MaterialTheme.colorScheme.onSurface
                                                           else
                                                            MaterialTheme.colorScheme.error
                                            )
                                        }
                                    }
                                    
                                    // Display active connections
                                    if (result.activeConnections.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            "Active Connections:",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Bold
                                        )
                                        result.activeConnections.forEach { connection ->
                                            Text(
                                                "• $connection",
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                    }
                                    
                                    // VPN and Proxy alerts
                                    if (result.vpnInUse) {
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            "⚠️ VPN detected",
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                    }
                                    
                                    if (result.proxyDetected) {
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            "⚠️ Proxy detected",
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                    }
                                }
                            }
                            )
                        
                        // File System Analysis
                            DetectionResultItem(
                            "File System Security",
                            !result.hasFileSystemAnomalies,
                            Icons.Default.Folder,
                            details = result.fileSystemAnalysisDetails
                        )
                        
                        // Battery & Sensor Analysis
                            DetectionResultItem(
                            "Battery & Sensor Analysis",
                            !result.hasBatteryAnomalies,
                            Icons.Default.BatteryChargingFull,
                            details = result.batteryAnalysisDetails
                        )
                        
                        // Code Injection Detection
                            DetectionResultItem(
                            "Code Injection Detection",
                            !result.hasCodeInjection,
                            Icons.Default.BugReport,
                            details = result.codeInjectionDetails
                        )
                        
                        // Device Identity
                            DetectionResultItem(
                                "Device Identity",
                            !result.hasIdentitySpoofing,
                            Icons.Default.Phonelink,
                            details = result.deviceIdentityDetails
                            )
                        
                        // Debug Detection
                            DetectionResultItem(
                            "Debug & Development Tools",
                            !result.hasDebugExposure,
                            Icons.Default.Build,
                            details = result.debugAnalysisDetails
                        )
                        
                        // Data Protection
                            DetectionResultItem(
                            "Data Protection",
                            !result.hasClipboardInterception,
                            Icons.Default.ContentCopy,
                            details = result.dataProtectionDetails
                        )
                        
                        // APK Analysis
                            DetectionResultItem(
                            "Side-Loaded APK Analysis",
                            !result.hasSuspiciousAPKs,
                            Icons.Default.InstallMobile,
                            details = result.apkAnalysisDetails
                        )
                        
                        // Virtualization Detection
                            DetectionResultItem(
                            "Virtualization Detection",
                            !result.hasVirtualization,
                            Icons.Default.Computer,
                            details = result.virtualizationDetails
                        )
                        
                        // Persistence Analysis
                            DetectionResultItem(
                            "Persistence Analysis",
                            !result.hasPersistenceMechanisms,
                            Icons.Default.Refresh,
                            details = result.persistenceAnalysisDetails
                        )
                        
                        // Real-time Integrity
                            DetectionResultItem(
                                "System Integrity",
                            !result.hasIntegrityIssues,
                            Icons.Default.Security,
                            details = result.integrityAnalysisDetails
                        )
                    } else if (selectedScanType == ScanType.Blockchain) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        
                        Text(
                            "Blockchain Security Analysis",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        
                        result.blockchainData?.let { blockchainData ->
                            // Blockchain Verification
                            DetectionResultItem(
                                "Blockchain Verification",
                                blockchainData.isAuthentic,
                                Icons.Default.VerifiedUser
                            )
                            
                            // Community Reports
                            DetectionResultItem(
                                "Community Reports",
                                blockchainData.communityReports == 0,
                                Icons.Default.People
                            )
                            
                            // Energy Impact
                            DetectionResultItem(
                                "Energy Impact",
                                blockchainData.energyImpact < 0.5f,
                                Icons.Default.BatteryChargingFull
                            )
                            
                            // AR Threats
                            if (blockchainData.arThreats.isNotEmpty()) {
                                Text(
                                    "AR Threat Visualization",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 8.dp)
                                )
                                
                                blockchainData.arThreats.forEach { threat ->
                                    DetectionResultItem(
                                        threat.description,
                                        threat.intensity < 0.5f,
                                        when (threat.threatType) {
                                            BlockchainScanService.ThreatType.MALICIOUS_APP -> Icons.Default.Warning
                                            BlockchainScanService.ThreatType.SUSPICIOUS_PERMISSION -> Icons.Default.Lock
                                            BlockchainScanService.ThreatType.ENERGY_DRAIN -> Icons.Default.BatteryChargingFull
                                            BlockchainScanService.ThreatType.NETWORK_THREAT -> Icons.Default.NetworkCheck
                                            BlockchainScanService.ThreatType.SYSTEM_MODIFICATION -> Icons.Default.Build
                                        }
                                    )
                                }
                            }
                            
                            // Emotional AI Companion
                            Text(
                                "AI Security Companion",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                            
                            Text(
                                blockchainData.securityNarrative,
                                style = MaterialTheme.typography.bodyMedium,
                                color = when (blockchainData.emotionalState) {
                                    in 0.7f..1.0f -> Color.Green
                                    in 0.4f..0.7f -> Color.Yellow
                                    else -> Color.Red
                                }
                            )
                            
                            // Gamification
                            if (blockchainData.gamificationPoints > 0) {
                                Text(
                                    "Security Points: ${blockchainData.gamificationPoints}",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 8.dp)
                                )
                                
                                LinearProgressIndicator(
                                    progress = { (blockchainData.gamificationPoints / 180f).coerceIn(0f, 1f) },
                                    modifier = Modifier.fillMaxWidth(),
                                    color = MaterialTheme.colorScheme.primary,
                                    trackColor = MaterialTheme.colorScheme.primaryContainer,
                                    strokeCap = StrokeCap.Round
                                )
                            }
                        }
                    }

                    if (result.isCloneDetected) {
                        var showDetailedReport by remember { mutableStateOf(false) }
                        
                        OutlinedButton(
                            onClick = { showDetailedReport = true },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("View Detailed Report")
                        }

                        if (showDetailedReport) {
                            AlertDialog(
                                onDismissRequest = { showDetailedReport = false },
                                title = { Text("Detailed Security Report") },
                                text = {
                                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text("Security Analysis Results:", fontWeight = FontWeight.Bold)
                                        
                                        // Basic Security
                                        Text("1. Basic Security:", fontWeight = FontWeight.Medium)
                                        Text("• Root Status: ${if (!result.isRooted) "✅ Secure" else "❌ Compromised"}")
                                        Text("• App Signature: ${if (result.hasValidSignature) "✅ Valid" else "❌ Invalid"}")
                                        Text("• System Properties: ${if (!result.hasSuspiciousProps) "✅ Clean" else "❌ Suspicious"}")
                                        Text("• Installation Source: ${if (result.hasValidInstaller) "✅ Trusted" else "❌ Untrusted"}")
                                        Text("• Device Identifiers: ${if (result.hasConsistentIds) "✅ Consistent" else "❌ Inconsistent"}")
                                        
                                        if (selectedScanType == ScanType.Deep) {
                                            // Advanced Security
                                            Text("\n2. Advanced Security:", fontWeight = FontWeight.Medium)
                                            if (result.hasAnomalies) Text("• System Anomalies Detected")
                                            if (result.firmwareTampered) Text("• Firmware Tampering Detected")
                                            if (result.hasHiddenApps) Text("• Hidden Apps Found")
                                            if (result.hasCertificateIssues) Text("• Certificate Chain Issues")
                                            if (result.hasCryptoWeaknesses) Text("• Cryptographic Weaknesses")
                                            if (result.hasHookingFrameworks) Text("• Hooking Frameworks Detected")
                                            if (result.hasSuspiciousNetwork) Text("• Suspicious Network Activity")
                                            if (result.hasFileSystemAnomalies) Text("• File System Anomalies")
                                            if (result.hasBatteryAnomalies) Text("• Battery Behavior Anomalies")
                                            if (result.hasCodeInjection) Text("• Code Injection Detected")
                                            if (result.hasIdentitySpoofing) Text("• Device Identity Spoofing")
                                            if (result.hasDebugExposure) Text("• Debug Exposure Detected")
                                            if (result.hasClipboardInterception) Text("• Clipboard Interception")
                                            if (result.hasSuspiciousAPKs) Text("• Suspicious Side-Loaded Apps")
                                            if (result.hasVirtualization) Text("• Virtualization Detected")
                                            if (result.hasPersistenceMechanisms) Text("• Persistence Mechanisms")
                                            if (result.hasIntegrityIssues) Text("• System Integrity Issues")
                                        }
                                        
                                        Spacer(modifier = Modifier.height(8.dp))
                                        
                                        Text("Recommendations:", fontWeight = FontWeight.Bold)
                                        Text("• Uninstall suspicious apps")
                                        Text("• Update system to latest version")
                                        Text("• Enable device encryption")
                                        Text("• Install security updates")
                                        Text("• Monitor app permissions")
                                        if (selectedScanType == ScanType.Deep) {
                                            Text("• Review advanced security settings")
                                            Text("• Check for system modifications")
                                            Text("• Monitor network traffic")
                                            Text("• Review installed certificates")
                                        }
                                    }
                                },
                                confirmButton = {
                                    TextButton(onClick = { showDetailedReport = false }) {
                                        Text("Close")
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }

    // Root Status Details Dialog
    if (showRootStatusDetails && detectionResult?.rootStatus != null) {
        val rootStatus = detectionResult!!.rootStatus!!
        AlertDialog(
            onDismissRequest = { showRootStatusDetails = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Root Status Details")
                }
            },
            text = {
                Column {
                    Text(
                        "Root Detection Results:",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    if (rootStatus.rootFiles.isNotEmpty()) {
                        Text("Root Files Found:", fontWeight = FontWeight.Medium)
                        rootStatus.rootFiles.forEach {
                            Text("• $it", style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    
                    if (rootStatus.rootPackages.isNotEmpty()) {
                        Text("Root Management Apps:", fontWeight = FontWeight.Medium)
                        rootStatus.rootPackages.forEach {
                            Text("• $it", style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    
                    if (rootStatus.rootProperties.isNotEmpty()) {
                        Text("Modified System Properties:", fontWeight = FontWeight.Medium)
                        rootStatus.rootProperties.forEach {
                            Text("• $it", style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    
                    if (rootStatus.developerMode) {
                        Text("• Developer Mode: Enabled", fontWeight = FontWeight.Medium)
                    }
                    
                    if (rootStatus.testKeys) {
                        Text("• Test Keys: Present", fontWeight = FontWeight.Medium)
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        "Root access exposes your device to serious security risks including data theft, malware infection, and system compromise.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showRootStatusDetails = false }) {
                    Text("Close")
                }
            }
        )
    }
    
    // Suspicious App Details Dialog
    if (showCloneAppDetails && detectionResult?.maliciousApps?.isNotEmpty() == true) {
        AlertDialog(
            onDismissRequest = { showCloneAppDetails = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Suspicious App Details")
                }
            },
            text = {
    Column(
                    modifier = Modifier.verticalScroll(rememberScrollState())
                ) {
                    detectionResult?.maliciousApps?.forEach { app ->
        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                                    app.appName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                                Text(
                                    app.packageName,
                                    style = MaterialTheme.typography.bodySmall
                                )
                                
                                Spacer(modifier = Modifier.height(8.dp))
                                
                                Row(
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    val threatColor = when (app.threatLevel) {
                                        ThreatLevel.CRITICAL -> MaterialTheme.colorScheme.error
                                        ThreatLevel.HIGH -> Color(0xFFFF6D00)
                                        ThreatLevel.MEDIUM -> Color(0xFFFFB300)
                                        else -> Color(0xFF689F38)
                                    }
                                    
                    Text(
                                        "Threat Level:",
                                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Surface(
                                        color = threatColor,
                                        shape = RoundedCornerShape(4.dp),
                                        modifier = Modifier.padding(4.dp)
                                    ) {
                                        Text(
                                            app.threatLevel.toString(),
                                            color = Color.White,
                                            style = MaterialTheme.typography.labelMedium,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                                
                                Spacer(modifier = Modifier.height(8.dp))
                                
                                // Show installer info if available
                                app.installerInfo?.let { installer ->
                                    Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                                            "Installation Source:",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        
                                        val sourceColor = if (installer.isTrustedSource) 
                                            Color(0xFF689F38) else MaterialTheme.colorScheme.error
                                        
                                        Surface(
                                            color = sourceColor,
                                            shape = RoundedCornerShape(4.dp),
                                            modifier = Modifier.padding(4.dp)
                                        ) {
                                            Text(
                                                installer.installerName ?: "Unknown",
                                                color = Color.White,
                                                style = MaterialTheme.typography.labelMedium,
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                            )
                                        }
                                    }
                                    
                                    Spacer(modifier = Modifier.height(8.dp))
                                }
                                
                                if (app.failedChecks.isNotEmpty()) {
                    Text(
                                        "Failed Security Checks:",
                                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    
                                    app.failedChecks.forEach { check ->
                                        Text(
                                            "• ${check.name.replace('_', ' ')}",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                    
                                    Spacer(modifier = Modifier.height(8.dp))
                                }
                                
                                if (app.behaviorAnomalies.isNotEmpty()) {
                Text(
                                        "Suspicious Behaviors:",
                    style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    
                                    app.behaviorAnomalies.forEach { anomaly ->
                            Text(
                                            "• $anomaly",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                    
                                    Spacer(modifier = Modifier.height(8.dp))
                                }
                                
                                if (app.recommendedActions.isNotEmpty()) {
                                                Text(
                                        "Recommended Actions:",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium
                                                )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    
                                    app.recommendedActions.forEach { action ->
                                                Text(
                                            "• $action",
                                                    style = MaterialTheme.typography.bodySmall
                                                )
                                            }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showCloneAppDetails = false }) {
                    Text("Close")
                }
            }
        )
    }
}

@Composable
fun HoneypotScreen(
    cloneDetectionService: CloneDetectionService,
    emotionalDeceptionManager: EmotionalDeceptionManager,
    modifier: Modifier = Modifier
) {
    var showEmotionalTrapLogDialog by remember { mutableStateOf(false) }
    val edeActive = remember { mutableStateOf(emotionalDeceptionManager.isServiceActive()) }
    
    // Toggle EDE service when switch is toggled
    val toggleEdeService: (Boolean) -> Unit = { active ->
        if (active) {
            emotionalDeceptionManager.startService()
        } else {
            emotionalDeceptionManager.stopService()
        }
        edeActive.value = active
    }
    
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Honeypot Feature",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        
        // Standard Honeypot Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Standard Honeypot",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                
                Text(
                    "Honeypot monitoring is active",
                    style = MaterialTheme.typography.bodyLarge
                )
                
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    progress = 1f,
                    color = Color.Green,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant
                )
            }
        }
        
        // Emotional Deception Environment Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Cognitive Trap Mode",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Switch(
                        checked = edeActive.value,
                        onCheckedChange = { 
                            toggleEdeService(it) 
                        },
                        thumbContent = if (edeActive.value) {
                            {
                                Icon(
                                    imageVector = Icons.Default.Psychology,
                                    contentDescription = null,
                                    modifier = Modifier.size(SwitchDefaults.IconSize)
                                )
                            }
                        } else null
                    )
                }
                
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 8.dp),
                    thickness = 1.dp,
                    color = MaterialTheme.colorScheme.outlineVariant
                )
                
                Text(
                    "Emotional Deception Environment (EDE)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                
                Text(
                    "Simulates emotional user behavior to bait emotion-aware malware into revealing itself",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                AnimatedVisibility(
                    visible = edeActive.value,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // Status indicators for active EDE
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            StatisticItem(
                                value = "3",
                                label = "Active Traps",
                                icon = Icons.Default.BugReport
                            )
                            
                            StatisticItem(
                                value = "12",
                                label = "Interactions",
                                icon = Icons.Default.TouchApp
                            )
                            
                            StatisticItem(
                                value = "1",
                                label = "Suspicious",
                                icon = Icons.Default.Warning
                            )
                        }
                        
                        // Active personalities
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Person,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text(
                                "Active personas: Financial Stress, Anxiety",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        
                        // Recent activity
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Timer,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text(
                                "Last activity: 2 minutes ago (Banking form trap)",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        
                        // View emotional trap log button
                        Button(
                            onClick = { showEmotionalTrapLogDialog = true },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                imageVector = Icons.Default.List,
                                contentDescription = null
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text("View Emotional Trap Log")
                        }
                    }
                }
                
                AnimatedVisibility(
                    visible = !edeActive.value,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            "Cognitive Trap Mode is currently inactive",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.outline
                        )
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Info,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text(
                                "Toggle the switch to activate emotional behavior simulation",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
        
        // Emotional trap explanation card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.Help,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        "How Emotional Deception Works",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                
                Text(
                    "The Emotional Deception Environment creates simulated emotional user behavior " +
                    "patterns to detect malware that activates during moments of user stress, anxiety, " +
                    "or urgency. This trap detects screen captures, sensor activations, and other " +
                    "suspicious behaviors that target emotionally vulnerable users.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
    
    // Dialog to show emotional trap logs
    if (showEmotionalTrapLogDialog) {
        AlertDialog(
            onDismissRequest = { showEmotionalTrapLogDialog = false },
            title = { Text("Emotional Trap Activity Log") },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Simulated log entries
                    listOf(
                        Triple("Financial Stress", "Rapid bank login attempt", "10 minutes ago"),
                        Triple("Anxiety", "Multiple navigation path changes", "25 minutes ago"),
                        Triple("Financial Stress", "Cryptocurrency wallet access", "42 minutes ago"),
                        Triple("Personal Crisis", "Emergency contact information accessed", "1 hour ago"),
                        Triple("Anxiety", "Hesitant input with multiple corrections", "1.5 hours ago")
                    ).forEach { (emotionalState, action, timeAgo) ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        emotionalState,
                                        style = MaterialTheme.typography.labelLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                    
                                    Text(
                                        timeAgo,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.outline
                                    )
                                }
                                
                                Text(
                                    action,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showEmotionalTrapLogDialog = false }) {
                    Text("Close")
                }
            }
        )
    }
}

@Composable
fun NetworkScreen(
    networkMonitorService: NetworkMonitorService,
    networkMirrorReflectionService: NetworkMirrorReflectionService,
    modifier: Modifier = Modifier
) {
    // Network stats state
    var networkStats by remember { mutableStateOf(NetworkMonitorService.NetworkStats(0L, 0L, "Unknown", emptyList(), emptyList(), emptyList(), false, false)) }
    
    // Update network stats periodically
    LaunchedEffect(Unit) {
        while (true) {
            try {
                // Use the NetworkMonitorService to get network statistics
                networkStats = networkMonitorService.getNetworkStats()
                
                // Monitor network changes to trigger stats refresh
                networkMonitorService.monitorNetworkChanges().collect { state ->
                    // Refresh network stats when network state changes
                    networkStats = networkMonitorService.getNetworkStats()
                }
                
                delay(5000) // Update every 5 seconds
            } catch (e: Exception) {
                // Handle exceptions
                e.printStackTrace()
                delay(10000) // Wait longer before retry if there's an error
            }
        }
    }
    
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Network Overview Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Network Overview",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    NetworkStatCard(
                        networkStats.activeNetworkType,
                        "Connection Type",
                        when(networkStats.activeNetworkType) {
                            "WiFi" -> Icons.Default.Wifi
                            "Mobile Data" -> Icons.Default.NetworkCell
                            "VPN" -> Icons.Default.VpnKey
                            else -> Icons.Default.NetworkCheck
                        },
                        modifier = Modifier.weight(1f)
                    )
                    
                    NetworkStatCard(
                        networkStats.ipAddresses.size.toString(),
                        "IP Addresses",
                        Icons.Default.Link,
                        modifier = Modifier.weight(1f)
                    )
                    
                    NetworkStatCard(
                        if (networkStats.vpnInUse || networkStats.proxyDetected) "Warning" else "Secure",
                        "Network Status",
                        if (networkStats.vpnInUse || networkStats.proxyDetected) Icons.Default.Warning else Icons.Default.Security,
                        modifier = Modifier.weight(1f),
                        valueColor = if (networkStats.vpnInUse || networkStats.proxyDetected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                    )
                }
            }
        }

        // Network Traffic Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Network Traffic",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                // Calculate traffic ratio for progress indicator
                val totalTraffic = networkStats.uploadTraffic + networkStats.downloadTraffic
                val uploadRatio = if (totalTraffic > 0) networkStats.uploadTraffic.toFloat() / totalTraffic else 0f
                
                LinearProgressIndicator(
                    progress = uploadRatio,
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.primaryContainer,
                    strokeCap = StrokeCap.Round
                )
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("Upload")
                        Text(
                            String.format("%.2f MB", networkStats.uploadTraffic / (1024f * 1024f)),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("Download")
                        Text(
                            String.format("%.2f MB", networkStats.downloadTraffic / (1024f * 1024f)),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }

        // Network Security Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Network Security",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                DetectionResultItem(
                    "SSL/TLS Verification",
                    true,
                    Icons.Default.Lock
                )
                
                DetectionResultItem(
                    "Network Encryption",
                    true,
                    Icons.Default.Security
                )
                
                DetectionResultItem(
                    "Firewall Status",
                    true,
                    Icons.Default.Shield
                )

                DetectionResultItem(
                    "VPN Connection",
                    !networkStats.vpnInUse,
                    Icons.Default.VpnKey,
                    details = if (networkStats.vpnInUse) "VPN detected" else "No VPN detected"
                )
                
                if (networkStats.proxyDetected) {
                    DetectionResultItem(
                        "Proxy Connection",
                        false,
                        Icons.Default.Warning,
                        details = "Proxy server detected"
                    )
                }
            }
        }

        // Active Connections Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "IP & DNS Information",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                // IP Addresses section
                if (networkStats.ipAddresses.isNotEmpty()) {
                    Text(
                        "IP Addresses:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    networkStats.ipAddresses.forEach { ip ->
                        Text(
                            "• $ip",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                }
                
                // DNS Servers section
                if (networkStats.dnsServers.isNotEmpty()) {
                    Text(
                        "DNS Servers:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    networkStats.dnsServers.forEach { dns ->
                        Text(
                            "• $dns",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (dns.startsWith("8.8.") || 
                                        dns.startsWith("1.1.1.") || 
                                        dns.startsWith("9.9.9.") ||
                                        dns.startsWith("208.67.") ||
                                        dns.startsWith("127.") ||
                                        dns.startsWith("192.168.") ||
                                        dns.startsWith("10."))
                                    MaterialTheme.colorScheme.onSurface
                                   else
                                    MaterialTheme.colorScheme.error
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                }
                
                // Active connections
                if (networkStats.activeConnections.isNotEmpty()) {
                    Text(
                        "Active Connections:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    networkStats.activeConnections.forEach { connection ->
                        Text(
                            "• $connection",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun NetworkStatCard(
    value: String,
    label: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    valueColor: Color = MaterialTheme.colorScheme.primary
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
        modifier = modifier
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = valueColor,
            modifier = Modifier.size(24.dp)
        )
        Text(
            value,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = valueColor
        )
        Text(
            label,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
fun NeuralFingerprintScreen(
    neuralFingerprintService: NeuralFingerprintService,
    modifier: Modifier = Modifier
) {
    // Delegate to the new implementation
    com.example.detection.ui.screens.NeuralFingerprintScreen(
        modifier = modifier,
        neuralFingerprintService = neuralFingerprintService
    )
}

@Composable
fun SettingsScreen(
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            "Settings",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            "Settings features will be implemented soon",
            style = MaterialTheme.typography.bodyLarge
        )
    }
}

// Add StatisticItem after SettingsScreen
@Composable
fun StatisticItem(
    value: String,
    label: String,
    icon: ImageVector
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp)
        )
        Text(
            value,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )
        Text(
            label,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

// Add getTimeAgo function after StatisticItem
fun getTimeAgo(timestamp: Long): String {
    val currentTime = System.currentTimeMillis()
    val diff = currentTime - timestamp

    return when {
        diff < 60 * 1000 -> "just now"
        diff < 60 * 60 * 1000 -> "${diff / (60 * 1000)} minutes ago"
        diff < 24 * 60 * 60 * 1000 -> "${diff / (60 * 60 * 1000)} hours ago"
        diff < 7 * 24 * 60 * 60 * 1000 -> "${diff / (24 * 60 * 60 * 1000)} days ago"
        else -> SimpleDateFormat("MMM dd", Locale.getDefault()).format(Date(timestamp))
    }
}

// Add DetectionResultItem composable
@Composable
fun DetectionResultItem(
    label: String,
    isValid: Boolean,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    details: String? = null,
    expandedContent: @Composable (() -> Unit)? = null
) {
    var expanded by remember { mutableStateOf(false) }
    
    Column(modifier = modifier) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (isValid) Color.Green else Color.Red,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                label,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f)
            )
            Icon(
                imageVector = if (isValid) Icons.Default.CheckCircle else Icons.Default.Cancel,
                contentDescription = null,
                tint = if (isValid) Color.Green else Color.Red
            )
            if (details != null || expandedContent != null) {
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = "Expand details",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
        
        if (expanded && details != null) {
            Text(
                details,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 32.dp, top = 4.dp, bottom = 4.dp)
            )
        }
        
        if (expanded && expandedContent != null) {
            Box(modifier = Modifier.padding(top = 8.dp)) {
                expandedContent()
            }
        }
    }
}