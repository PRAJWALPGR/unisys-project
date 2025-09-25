package com.example.detection.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.background
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Error
import androidx.compose.ui.res.painterResource
import androidx.compose.foundation.Image
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextOverflow
import com.example.detection.ui.viewmodels.AppAnalysisInfo
import com.example.detection.R

@Composable
fun AppTrustCard(
    app: AppAnalysisInfo,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App Icon (placeholder for now)
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            // App info
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = app.appName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                // Source info
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val (icon, color) = when {
                        app.installerStore.contains("Play Store") -> 
                            Pair(Icons.Default.Check, Color(0xFF00C853))
                        app.installerStore.contains("Galaxy") || 
                        app.installerStore.contains("AppGallery") || 
                        app.installerStore.contains("App Store") -> 
                            Pair(Icons.Default.Check, Color(0xFF2196F3))
                        app.isSystemApp -> 
                            Pair(Icons.Default.Check, Color(0xFF7B1FA2))
                        app.installerStore == "Unknown Source" -> 
                            Pair(Icons.Default.Warning, Color(0xFFFF6D00))
                        else -> 
                            Pair(Icons.Default.Info, Color(0xFF607D8B))
                    }
                    
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = color
                    )
                    
                    Spacer(modifier = Modifier.width(4.dp))
                    
                    Text(
                        text = "Source: ${app.installerStore}",
                        style = MaterialTheme.typography.bodySmall,
                        color = color
                    )
                }
            }
            
            Spacer(modifier = Modifier.width(8.dp))
            
            // Trust score indicator
            TrustScoreIndicator(trustScore = app.trustScore)
        }
        
        // Primary issue
        if (app.primaryIssue.isNotEmpty() && app.trustScore < 70) {
            Surface(
                color = when {
                    app.trustScore < 30 -> Color(0xFFFFEBEE)
                    app.trustScore < 50 -> Color(0xFFFFF3E0)
                    else -> Color(0xFFFFFDE7)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = when {
                            app.trustScore < 30 -> Icons.Default.Error
                            app.trustScore < 50 -> Icons.Default.Warning
                            else -> Icons.Default.Info
                        },
                        contentDescription = null,
                        tint = when {
                            app.trustScore < 30 -> Color(0xFFE53935)
                            app.trustScore < 50 -> Color(0xFFFF6D00)
                            else -> Color(0xFFFFA000)
                        },
                        modifier = Modifier.size(16.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = app.primaryIssue,
                        style = MaterialTheme.typography.bodySmall,
                        color = when {
                            app.trustScore < 30 -> Color(0xFFE53935)
                            app.trustScore < 50 -> Color(0xFFFF6D00)
                            else -> Color(0xFFFFA000)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun TrustScoreIndicator(trustScore: Int) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(RoundedCornerShape(20.dp))
            .background(
                when {
                    trustScore >= 80 -> Color(0xFF00C853)
                    trustScore >= 60 -> Color(0xFF7CB342)
                    trustScore >= 40 -> Color(0xFFFFA000)
                    trustScore >= 20 -> Color(0xFFFF6D00)
                    else -> Color(0xFFE53935)
                }
            ),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "$trustScore",
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            color = Color.White
        )
    }
}

@Composable
fun SourceSummaryCard(
    playStoreCount: Int,
    systemAppCount: Int,
    unknownSourceCount: Int,
    otherStoreCount: Int
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(
                text = "App Source Summary",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                SourceCountItem(
                    count = playStoreCount,
                    label = "Play Store",
                    color = Color(0xFF00C853)
                )
                
                SourceCountItem(
                    count = systemAppCount,
                    label = "System",
                    color = Color(0xFF7B1FA2)
                )
                
                SourceCountItem(
                    count = otherStoreCount,
                    label = "Other Stores",
                    color = Color(0xFF2196F3)
                )
                
                SourceCountItem(
                    count = unknownSourceCount,
                    label = "Unknown",
                    color = Color(0xFFFF6D00)
                )
            }
        }
    }
}

@Composable
fun SourceCountItem(
    count: Int,
    label: String,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(24.dp))
                .background(color.copy(alpha = 0.2f)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = count.toString(),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = color
            )
        }
        
        Spacer(modifier = Modifier.height(4.dp))
        
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun WarningCard(
    unknownSourceCount: Int,
    onDeepScanClick: () -> Unit
) {
    if (unknownSourceCount > 0) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFFFF3E0)
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = Color(0xFFFF6D00)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = if (unknownSourceCount == 1) 
                            "1 app from unknown source detected" 
                        else 
                            "$unknownSourceCount apps from unknown sources detected",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100)
                    )
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Apps from unknown sources may pose security risks. We recommend only installing apps from trusted sources like the Google Play Store.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(0xFFE65100)
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = onDeepScanClick,
                    modifier = Modifier.align(Alignment.End),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFFFF6D00)
                    )
                ) {
                    Text("Run Deep Scan")
                }
            }
        }
    }
}

@Composable
fun DeepScanDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text("Deep Scan Analysis")
        },
        text = {
            Column {
                Text(
                    "A deep scan will analyze:")
                Spacer(modifier = Modifier.height(8.dp))
                
                BulletItem("Installation sources")
                BulletItem("App permissions")
                BulletItem("Package signatures")
                BulletItem("Runtime behavior")
                BulletItem("Network connections")
                
                Spacer(modifier = Modifier.height(8.dp))
                Text("This process may take a few minutes to complete.")
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onConfirm()
                    onDismiss()
                }
            ) {
                Text("Start Scan")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss
            ) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun BulletItem(text: String) {
    Row(
        modifier = Modifier.padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(MaterialTheme.colorScheme.primary)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text)
    }
} 