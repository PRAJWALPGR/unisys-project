package com.example.detection.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.ArrowDropUp
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Store
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.detection.service.NeuralFingerprintService
import com.example.detection.ui.theme.NfDangerRed
import com.example.detection.ui.theme.NfDarkSurface
import com.example.detection.ui.theme.NfHolographicGradientEnd
import com.example.detection.ui.theme.NfHolographicGradientStart
import com.example.detection.ui.theme.NfInfoBlue
import com.example.detection.ui.theme.NfNeonBlue
import com.example.detection.ui.theme.NfNeonGreen
import com.example.detection.ui.theme.NfNeonPurple
import com.example.detection.ui.theme.NfNeonRed
import com.example.detection.ui.theme.NfNeonYellow
import com.example.detection.ui.theme.NfPulseEnd
import com.example.detection.ui.theme.NfPulseStart
import com.example.detection.ui.theme.NfSafeGreen
import com.example.detection.ui.theme.NfSecurityCritical
import com.example.detection.ui.theme.NfSecurityHigh
import com.example.detection.ui.theme.NfSecurityLow
import com.example.detection.ui.theme.NfSecurityMedium
import com.example.detection.ui.theme.NfWarningOrange
import com.example.detection.ui.theme.NfTextPrimary
import com.example.detection.ui.theme.NfTextSecondary
import com.example.detection.ui.theme.NfCardBackground
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.text.font.FontStyle

@Composable
fun SecurityScoreCircle(
    score: Int,
    modifier: Modifier = Modifier,
    size: Int = 200,
    pulsingEffect: Boolean = true
) {
    val scoreColor = when {
        score >= 90 -> NfSecurityHigh
        score >= 70 -> NfSecurityMedium
        score >= 50 -> NfSecurityLow
        else -> NfSecurityCritical
    }
    
    val infiniteTransition = rememberInfiniteTransition(label = "securityPulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )
    
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(size.dp)
            .drawBehind {
                // Draw outer circle with gradient
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            scoreColor.copy(alpha = 0.1f),
                            scoreColor.copy(alpha = 0.05f),
                            Color.Transparent
                        ),
                        center = Offset(this.size.width / 2, this.size.height / 2),
                        radius = this.size.width * 0.6f
                    ),
                    radius = this.size.width * 0.6f,
                    center = Offset(this.size.width / 2, this.size.height / 2)
                )
                
                if (pulsingEffect) {
                    // Draw pulsing effect
                    drawCircle(
                        color = scoreColor.copy(alpha = 0.1f * pulseAlpha),
                        radius = this.size.width * 0.55f * (1 + 0.1f * pulseAlpha),
                        center = Offset(this.size.width / 2, this.size.height / 2)
                    )
                }
                
                // Draw progress arc
                val sweepAngle = 360f * (score / 100f)
                drawArc(
                    color = scoreColor,
                    startAngle = -90f,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    style = Stroke(width = 12f, cap = StrokeCap.Round)
                )
            }
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "$score",
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold,
                color = scoreColor
            )
            
            Text(
                text = "Security Score",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
            )
        }
    }
}

@Composable
fun NeuralFingerprintVisualization(
    modifier: Modifier = Modifier,
    animating: Boolean = true
) {
    val infiniteTransition = rememberInfiniteTransition(label = "fpAnim")
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(20000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )
    
    val innerRotation by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "innerRotation"
    )
    
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.97f,
        targetValue = 1.03f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )
    
    Canvas(
        modifier = modifier
            .size(220.dp)
            .padding(16.dp)
    ) {
        val center = Offset(size.width / 2, size.height / 2)
        val radius = size.minDimension / 2.5f
        
        // Draw outer ring
        rotate(rotation) {
            for (i in 0 until 36) {
                val angle = i * 10f
                val length = if (i % 3 == 0) 0.2f else 0.1f
                val angleRad = Math.toRadians(angle.toDouble())
                val startX = center.x + radius * cos(angleRad).toFloat()
                val startY = center.y + radius * sin(angleRad).toFloat()
                val endX = center.x + (radius + radius * length) * cos(angleRad).toFloat()
                val endY = center.y + (radius + radius * length) * sin(angleRad).toFloat()
                
                drawLine(
                    color = NfNeonBlue.copy(alpha = 0.7f),
                    start = Offset(startX, startY),
                    end = Offset(endX, endY),
                    strokeWidth = 2.5f
                )
            }
        }
        
        // Draw inner circles and patterns
        rotate(innerRotation) {
            // Fingerprint-like arcs
            val arcColors = listOf(NfNeonBlue, NfNeonPurple, NfNeonGreen)
            for (i in 0 until 8) {
                val startAngle = (i * 45f + (rotation / 4)) % 360
                val sweepAngle = 120f
                val arcColor = arcColors[i % arcColors.size]
                val arcRadius = radius * (0.4f + i * 0.06f) * pulseScale
                
                drawArc(
                    color = arcColor.copy(alpha = 0.5f),
                    startAngle = startAngle,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    style = Stroke(width = 1.5f)
                )
            }
            
            // Central fingerprint pattern
            drawCircle(
                color = NfNeonPurple.copy(alpha = 0.2f),
                radius = radius * 0.3f * pulseScale,
                center = center
            )
            
            // Fingerprint ridges (simplified)
            for (i in 0 until 5) {
                val startAngle = (i * 72f) % 360
                val arcRadius = radius * (0.15f + i * 0.03f)
                
                drawArc(
                    color = NfNeonGreen.copy(alpha = 0.8f),
                    startAngle = startAngle,
                    sweepAngle = 36f,
                    useCenter = false,
                    style = Stroke(width = 2f)
                )
            }
        }
        
        // Draw pulsing glow
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    NfPulseEnd.copy(alpha = 0.3f),
                    NfPulseStart
                ),
                center = center,
                radius = radius * 0.8f * pulseScale
            ),
            radius = radius * 0.8f * pulseScale,
            center = center
        )
        
        // Draw central point
        drawCircle(
            color = NfNeonBlue,
            radius = 4f,
            center = center
        )
    }
}

@Composable
fun AppTrustCard(
    appName: String,
    trustScore: Float,
    primaryIssue: String,
    packageName: String,
    onViewDetails: (String) -> Unit,
    sourceInfo: String = "Unknown Source"
) {
    var expanded by remember { mutableStateOf(!primaryIssue.isNullOrEmpty() && trustScore < 70f) }
    
    val isPlayStore = sourceInfo.contains("Play Store")
    val isSystemApp = sourceInfo.contains("System")
    val isUnknownSource = sourceInfo == "Unknown Source"
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                trustScore < 50f -> Color(0xFFFFEBEE) // Light red for low trust
                trustScore < 70f -> Color(0xFFFFF8E1) // Light amber for medium trust
                else -> Color(0xFFF5F5F5) // Light grey for trusted
            }
        ),
        border = BorderStroke(
            width = 1.dp,
            color = when {
                trustScore < 50f -> NfDangerRed.copy(alpha = 0.5f)
                trustScore < 70f -> Color(0xFFFFA000).copy(alpha = 0.5f) // Amber
                else -> Color(0xFFE0E0E0)
            }
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 2.dp
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // App info
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = appName,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = NfTextPrimary
                        )
                        
                        Spacer(modifier = Modifier.width(8.dp))
                        
                        // Source badge
                        val sourceColor = when {
                            isPlayStore -> NfSafeGreen
                            isSystemApp -> NfNeonBlue
                            else -> NfDangerRed
                        }
                        
                        Box(
                            modifier = Modifier
                                .background(
                                    color = sourceColor.copy(alpha = 0.1f),
                                    shape = RoundedCornerShape(4.dp)
                                )
                                .border(
                                    width = 0.5.dp,
                                    color = sourceColor.copy(alpha = 0.3f),
                                    shape = RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(
                                    imageVector = when {
                                        isPlayStore -> Icons.Default.Verified
                                        isSystemApp -> Icons.Default.Shield
                                        else -> Icons.Default.Warning
                                    },
                                    contentDescription = null,
                                    tint = sourceColor,
                                    modifier = Modifier.size(12.dp)
                                )
                                
                                Text(
                                    text = when {
                                        isPlayStore -> "Play Store"
                                        isSystemApp -> "System App"
                                        else -> "Unknown Source"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = sourceColor,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                    
                    // Package name
                    Spacer(modifier = Modifier.height(4.dp))
                    
                    Text(
                        text = packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = NfTextSecondary
                    )
                    
                    // Full source info if different from the badge
                    if (sourceInfo != "Play Store" && sourceInfo != "System App" && sourceInfo != "Unknown Source") {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Source: $sourceInfo",
                            style = MaterialTheme.typography.bodySmall,
                            color = NfTextSecondary,
                            fontStyle = FontStyle.Italic
                        )
                    }
                }
                
                // Trust score indicator
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .padding(4.dp)
                ) {
                    CircularProgressIndicator(
                        progress = { 1f },
                        modifier = Modifier.fillMaxSize(),
                        color = Color(0xFFEEEEEE),
                        strokeWidth = 4.dp
                    )
                    
                    CircularProgressIndicator(
                        progress = { trustScore / 100f },
                        modifier = Modifier.fillMaxSize(),
                        color = when {
                            trustScore < 50f -> NfDangerRed
                            trustScore < 70f -> Color(0xFFFFA000) // Amber
                            else -> NfSafeGreen
                        },
                        strokeWidth = 4.dp
                    )
                    
                    // Trust score value
                    Text(
                        text = trustScore.toInt().toString(),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        color = NfTextPrimary,
                        modifier = Modifier.align(Alignment.Center)
                    )
                }
            }
            
            // Expandable details
            if (expanded) {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider(thickness = 0.5.dp, color = Color(0xFFE0E0E0))
                Spacer(modifier = Modifier.height(8.dp))
                
                // Source verification info
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(vertical = 4.dp)
                ) {
                    Icon(
                        imageVector = when {
                            isPlayStore -> Icons.Default.Verified
                            isSystemApp -> Icons.Default.Shield
                            else -> Icons.Default.Warning
                        },
                        contentDescription = null,
                        tint = when {
                            isPlayStore -> NfSafeGreen
                            isSystemApp -> NfNeonBlue
                            else -> NfDangerRed
                        },
                        modifier = Modifier.size(16.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = when {
                            isPlayStore -> "Verified: Installed from Google Play Store"
                            isSystemApp -> "System App: Pre-installed by device manufacturer"
                            else -> "Warning: Installed from unknown source"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfTextSecondary
                    )
                }
                
                if (!primaryIssue.isNullOrEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    
                    Row(
                        verticalAlignment = Alignment.Top,
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        Icon(
                            imageVector = when {
                                trustScore < 50f -> Icons.Default.Error
                                trustScore < 70f -> Icons.Default.Warning
                                else -> Icons.Default.Info
                            },
                            contentDescription = null,
                            tint = when {
                                trustScore < 50f -> NfDangerRed
                                trustScore < 70f -> Color(0xFFFFA000) // Amber
                                else -> NfNeonBlue
                            },
                            modifier = Modifier.size(16.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(8.dp))
                        
                        Text(
                            text = primaryIssue,
                            style = MaterialTheme.typography.bodyMedium,
                            color = NfTextSecondary
                        )
                    }
                }
                
                if (isUnknownSource) {
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(NfDangerRed.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                            .padding(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = null,
                            tint = NfDangerRed,
                            modifier = Modifier.size(20.dp)
                        )
                        
                        Spacer(modifier = Modifier.width(8.dp))
                        
                        Text(
                            text = "Apps from unknown sources may pose security risks to your device.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = NfDangerRed
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Button(
                    onClick = { onViewDetails(packageName) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NfNeonBlue
                    ),
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(4.dp))
                    
                    Text("View Details")
                }
            }
        }
    }
}

@Composable
fun BulletPoint(
    text: String,
    completed: Boolean
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 2.dp)
    ) {
        Icon(
            imageVector = if (completed) Icons.Default.Check else Icons.Default.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (completed) NfSafeGreen else Color(0xFFBDBDBD),
            modifier = Modifier.size(16.dp)
        )
        
        Spacer(modifier = Modifier.width(8.dp))
        
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = if (completed) NfTextPrimary else NfTextSecondary
        )
    }
}

@Composable
fun ThreatHistoryItem(
    event: NeuralFingerprintService.ThreatHistoryEvent,
    onViewDetails: (NeuralFingerprintService.ThreatHistoryEvent) -> Unit,
    modifier: Modifier = Modifier
) {
    val severityColor = when (event.severity) {
        NeuralFingerprintService.ThreatSeverity.CRITICAL -> NfSecurityCritical
        NeuralFingerprintService.ThreatSeverity.HIGH -> NfSecurityLow
        NeuralFingerprintService.ThreatSeverity.MEDIUM -> NfSecurityMedium
        NeuralFingerprintService.ThreatSeverity.LOW -> NfSecurityHigh
        else -> NfInfoBlue
    }
    
    val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
    val formattedDate = dateFormat.format(Date(event.timestamp))
    
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable { onViewDetails(event) },
        colors = CardDefaults.cardColors(
            containerColor = NfDarkSurface
        ),
        border = if (event.severity == NeuralFingerprintService.ThreatSeverity.HIGH || 
                    event.severity == NeuralFingerprintService.ThreatSeverity.CRITICAL) {
            BorderStroke(1.dp, severityColor.copy(alpha = 0.5f))
        } else null
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(color = severityColor, shape = CircleShape)
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = event.description,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    text = formattedDate,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "AI Confidence: ${event.aiConfidence}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = NfNeonBlue
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    if (event.isResolved) {
                        Surface(
                            color = NfSecurityHigh.copy(alpha = 0.2f),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "Resolved",
                                style = MaterialTheme.typography.bodySmall,
                                color = NfSecurityHigh,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }
            
            if (!event.isResolved && 
                (event.severity == NeuralFingerprintService.ThreatSeverity.HIGH || 
                event.severity == NeuralFingerprintService.ThreatSeverity.CRITICAL)) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(
                            color = severityColor.copy(alpha = 0.2f),
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = "Critical",
                        tint = severityColor,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun ModelTrainingCard(
    trainingStatus: NeuralFingerprintService.ModelTrainingStatus,
    onStartTraining: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = NfDarkSurface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Neural AI Training",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            if (trainingStatus.isTraining) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = trainingStatus.currentStage,
                            style = MaterialTheme.typography.bodyMedium,
                            color = NfNeonBlue
                        )
                        
                        Text(
                            text = "ETA: ${trainingStatus.estimatedTimeRemaining}s",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    LinearProgressIndicator(
                        progress = { trainingStatus.progress },
                        modifier = Modifier.fillMaxWidth(),
                        color = NfNeonPurple,
                        trackColor = NfNeonPurple.copy(alpha = 0.2f)
                    )
                }
            } else if (trainingStatus.isAnalyzing) {
                Column {
                    Text(
                        text = "Analyzing APK: ${trainingStatus.analysisTarget?.substringAfterLast('/') ?: ""}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = NfNeonBlue
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    LinearProgressIndicator(
                        progress = { trainingStatus.analysisProgress },
                        modifier = Modifier.fillMaxWidth(),
                        color = NfNeonYellow,
                        trackColor = NfNeonYellow.copy(alpha = 0.2f)
                    )
                    
                    if (trainingStatus.analysisResult != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "Analysis Result: ${trainingStatus.analysisResult}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (trainingStatus.analysisResult.contains("No threats")) 
                                NfSecurityHigh else NfSecurityLow
                        )
                    }
                }
            } else {
                Text(
                    text = "Fine-tune the Neural Fingerprint AI model to improve detection accuracy. " +
                           "Advanced users can adjust sensitivity and test APK files.",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Button(
                    onClick = onStartTraining,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NfNeonPurple
                    ),
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Text("Start Training")
                }
            }
        }
    }
}

@Composable
fun CyberShieldAnimation(
    active: Boolean,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "shieldAnim")
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(10000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )
    
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.95f,
        targetValue = 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )
    
    var showActivation by remember { mutableStateOf(false) }
    val activationAlpha by animateFloatAsState(
        targetValue = if (showActivation) 1f else 0f,
        animationSpec = tween(500),
        label = "activationAlpha"
    )
    
    LaunchedEffect(active) {
        if (active) {
            showActivation = true
            delay(500)
            showActivation = false
        }
    }
    
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        // Shield background
        Canvas(
            modifier = Modifier
                .size(100.dp)
                .padding(8.dp)
        ) {
            rotate(rotation) {
                // Outer ring
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            NfNeonBlue.copy(alpha = 0.1f),
                            NfNeonBlue.copy(alpha = 0.05f),
                            Color.Transparent
                        )
                    ),
                    radius = size.minDimension / 2f * 1.2f * pulseScale
                )
                
                // Dashed circle
                val dashCount = 24
                val dashLength = 5f
                val gapLength = 10f
                val radius = size.minDimension / 2.2f * pulseScale
                val center = Offset(size.width / 2, size.height / 2)
                
                for (i in 0 until dashCount) {
                    val angle = (i * 360f / dashCount)
                    val startAngle = angle - dashLength / 2
                    val endAngle = angle + dashLength / 2
                    
                    drawArc(
                        color = NfNeonBlue.copy(alpha = 0.7f),
                        startAngle = startAngle,
                        sweepAngle = dashLength,
                        useCenter = false,
                        style = Stroke(width = 2f)
                    )
                }
                
                // Shield shape
                val shieldPath = Path().apply {
                    moveTo(center.x, center.y - radius * 0.6f)
                    lineTo(center.x + radius * 0.5f, center.y - radius * 0.3f)
                    lineTo(center.x + radius * 0.5f, center.y + radius * 0.3f)
                    lineTo(center.x, center.y + radius * 0.6f)
                    lineTo(center.x - radius * 0.5f, center.y + radius * 0.3f)
                    lineTo(center.x - radius * 0.5f, center.y - radius * 0.3f)
                    close()
                }
                
                drawPath(
                    path = shieldPath,
                    color = NfNeonBlue.copy(alpha = 0.3f)
                )
                
                drawPath(
                    path = shieldPath,
                    color = NfNeonBlue.copy(alpha = 0.8f),
                    style = Stroke(width = 2f)
                )
            }
        }
        
        // Activation flash
        if (activationAlpha > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .drawWithContent {
                        drawContent()
                        drawRect(
                            brush = Brush.radialGradient(
                                colors = listOf(
                                    NfNeonBlue.copy(alpha = 0.2f * activationAlpha),
                                    Color.Transparent
                                )
                            )
                        )
                    }
            )
        }
    }
}

@Composable
fun SecurityStatCard(
    value: String,
    label: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    valueColor: Color = NfNeonBlue,
    background: Color = NfDarkSurface
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = background
        )
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(16.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = valueColor,
                modifier = Modifier.size(28.dp)
            )
            
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = valueColor
            )
            
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun BorderStroke(
    width: androidx.compose.ui.unit.Dp,
    color: Color
): androidx.compose.foundation.BorderStroke {
    return androidx.compose.foundation.BorderStroke(width, color)
}

@Composable
fun HolographicCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "hologramAnim")
    val animatedDegrees by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(10000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )
    
    Box(
        modifier = modifier
            .drawWithCache {
                onDrawBehind {
                    rotate(animatedDegrees) {
                        drawRect(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    NfHolographicGradientStart,
                                    NfHolographicGradientEnd,
                                    NfHolographicGradientStart
                                ),
                                start = Offset(0f, 0f),
                                end = Offset(size.width, size.height)
                            )
                        )
                    }
                }
            }
            .clip(RoundedCornerShape(12.dp))
            .border(
                width = 1.dp,
                brush = Brush.linearGradient(
                    colors = listOf(
                        NfNeonBlue.copy(alpha = 0.5f),
                        NfNeonPurple.copy(alpha = 0.5f)
                    )
                ),
                shape = RoundedCornerShape(12.dp)
            )
            .blur(2.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    color = NfDarkSurface.copy(alpha = 0.85f)
                )
                .padding(16.dp)
        ) {
            content()
        }
    }
}

@Composable
fun NeuralActivityGraph(
    modifier: Modifier = Modifier,
    heightDp: Int = 100,
    animated: Boolean = true
) {
    val infiniteTransition = rememberInfiniteTransition(label = "graphAnim")
    val animationProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "progress"
    )
    
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(heightDp.dp)
    ) {
        val width = size.width
        val height = size.height
        val pointCount = 100
        val path = Path()
        val points = mutableListOf<Offset>()
        
        // Generate neural network activity-like pattern
        for (i in 0 until pointCount) {
            val x = width * i / pointCount
            
            // Create an animated wave pattern with multiple frequencies
            val progress = if (animated) (i.toFloat() / pointCount + animationProgress) % 1f else i.toFloat() / pointCount
            val y = height / 2 + 
                    (sin(progress * 2 * PI) * height * 0.2).toFloat() +
                    (sin(progress * 4 * PI) * height * 0.05).toFloat() +
                    (sin(progress * 8 * PI) * height * 0.025).toFloat()
            
            points.add(Offset(x, y))
            
            if (i == 0) {
                path.moveTo(x, y)
            } else {
                path.lineTo(x, y)
            }
        }
        
        // Draw the graph line
        drawPath(
            path = path,
            color = NfNeonBlue,
            style = Stroke(width = 2f)
        )
        
        // Draw some highlight points
        for (i in 0 until pointCount step 10) {
            if (i < points.size) {
                drawCircle(
                    color = NfNeonGreen,
                    radius = 3f,
                    center = points[i]
                )
            }
        }
        
        // Draw background grid lines
        val gridSpacing = height / 5
        for (i in 1 until 5) {
            val y = i * gridSpacing
            
            drawLine(
                color = NfNeonBlue.copy(alpha = 0.2f),
                start = Offset(0f, y),
                end = Offset(width, y),
                strokeWidth = 1f
            )
        }
        
        // Draw a few vertical grid lines
        val verticalLines = 10
        for (i in 1 until verticalLines) {
            val x = i * width / verticalLines
            
            drawLine(
                color = NfNeonBlue.copy(alpha = 0.1f),
                start = Offset(x, 0f),
                end = Offset(x, height),
                strokeWidth = 1f
            )
        }
    }
} 