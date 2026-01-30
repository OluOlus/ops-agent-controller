"""
Unit tests for ApprovalGate system
Requirements: 3.1, 3.4
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from src.approval_gate import ApprovalGate, ApprovalDecision
from src.models import ToolCall, ApprovalRequest, ExecutionMode


class TestApprovalGate:
    """Test ApprovalGate class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.approval_gate = ApprovalGate(storage_backend="memory", default_expiry_minutes=15)
        self.test_tool_call = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-1234567890abcdef0"},
            requires_approval=True
        )
        self.test_user_id = "test_user_123"
    
    def test_initialization(self):
        """Test ApprovalGate initialization"""
        gate = ApprovalGate(storage_backend="memory", default_expiry_minutes=30)
        
        assert gate.storage_backend == "memory"
        assert gate.default_expiry_minutes == 30
        assert gate._pending_approvals == {}
        assert gate._used_tokens == set()
        assert gate._approval_decisions == {}
    
    def test_generate_approval_token(self):
        """Test approval token generation"""
        token1 = self.approval_gate.generate_approval_token()
        token2 = self.approval_gate.generate_approval_token()
        
        # Tokens should be unique
        assert token1 != token2
        
        # Tokens should be hex strings of appropriate length (32 bytes = 64 hex chars)
        assert len(token1) == 64
        assert len(token2) == 64
        assert all(c in '0123456789abcdef' for c in token1)
        assert all(c in '0123456789abcdef' for c in token2)
    
    def test_create_approval_request_success(self):
        """Test successful approval request creation"""
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id,
            risk_level="high",
            expiry_minutes=30
        )
        
        assert approval_request.tool_call == self.test_tool_call
        assert approval_request.requested_by == self.test_user_id
        assert approval_request.risk_level == "high"
        assert approval_request.correlation_id == self.test_tool_call.correlation_id
        
        # Check expiry time is approximately correct (within 1 minute tolerance)
        expected_expiry = datetime.utcnow() + timedelta(minutes=30)
        time_diff = abs((approval_request.expires_at - expected_expiry).total_seconds())
        assert time_diff < 60  # Within 1 minute
        
        # Verify it's stored
        assert approval_request.token in self.approval_gate._pending_approvals
    
    def test_create_approval_request_default_expiry(self):
        """Test approval request creation with default expiry"""
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Check default expiry time (15 minutes)
        expected_expiry = datetime.utcnow() + timedelta(minutes=15)
        time_diff = abs((approval_request.expires_at - expected_expiry).total_seconds())
        assert time_diff < 60  # Within 1 minute
        
        # Check default risk level
        assert approval_request.risk_level == "medium"
    
    def test_create_approval_request_no_approval_required(self):
        """Test creating approval request for tool that doesn't require approval"""
        tool_call = ToolCall(tool_name="get_metrics", requires_approval=False)
        
        with pytest.raises(ValueError, match="Tool call does not require approval"):
            self.approval_gate.create_approval_request(
                tool_call=tool_call,
                requested_by=self.test_user_id
            )
    
    def test_create_approval_request_invalid_risk_level(self):
        """Test creating approval request with invalid risk level"""
        with pytest.raises(ValueError, match="Risk level must be"):
            self.approval_gate.create_approval_request(
                tool_call=self.test_tool_call,
                requested_by=self.test_user_id,
                risk_level="critical"
            )
    
    def test_validate_approval_token_success(self):
        """Test successful token validation"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Approve the request
        self.approval_gate.approve_request(
            token=approval_request.token,
            user_id=self.test_user_id,
            approved=True
        )
        
        # Validate token
        is_valid, reason = self.approval_gate.validate_approval_token(
            token=approval_request.token,
            user_id=self.test_user_id,
            tool_call=self.test_tool_call
        )
        
        assert is_valid is True
        assert reason == "Token is valid"
    
    def test_validate_approval_token_already_used(self):
        """Test validating already used token"""
        # Create and approve request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        self.approval_gate.approve_request(approval_request.token, self.test_user_id, True)
        
        # Consume the token
        self.approval_gate.consume_approval_token(approval_request.token)
        
        # Try to validate again
        is_valid, reason = self.approval_gate.validate_approval_token(
            token=approval_request.token,
            user_id=self.test_user_id,
            tool_call=self.test_tool_call
        )
        
        assert is_valid is False
        assert reason == "Token has already been used"
    
    def test_validate_approval_token_invalid_token(self):
        """Test validating invalid token"""
        is_valid, reason = self.approval_gate.validate_approval_token(
            token="invalid_token",
            user_id=self.test_user_id,
            tool_call=self.test_tool_call
        )
        
        assert is_valid is False
        assert reason == "Invalid or unknown token"
    
    def test_validate_approval_token_expired(self):
        """Test validating expired token"""
        # Create approval request with past expiry
        with patch('src.approval_gate.datetime') as mock_datetime:
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            approval_request = self.approval_gate.create_approval_request(
                tool_call=self.test_tool_call,
                requested_by=self.test_user_id,
                expiry_minutes=15
            )
        
        # Try to validate with current time
        is_valid, reason = self.approval_gate.validate_approval_token(
            token=approval_request.token,
            user_id=self.test_user_id,
            tool_call=self.test_tool_call
        )
        
        assert is_valid is False
        assert reason == "Token has expired"
    
    def test_validate_approval_token_tool_call_mismatch(self):
        """Test validating token with mismatched tool call"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Try to validate with different tool call
        different_tool_call = ToolCall(
            tool_name="ec2_stop",  # Different tool
            args={"instance_id": "i-1234567890abcdef0"},
            requires_approval=True
        )
        
        is_valid, reason = self.approval_gate.validate_approval_token(
            token=approval_request.token,
            user_id=self.test_user_id,
            tool_call=different_tool_call
        )
        
        assert is_valid is False
        assert reason == "Tool call does not match approved request"
    
    def test_validate_approval_token_unauthorized_user(self):
        """Test validating token with unauthorized user"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Try to validate with different user
        is_valid, reason = self.approval_gate.validate_approval_token(
            token=approval_request.token,
            user_id="different_user",
            tool_call=self.test_tool_call
        )
        
        assert is_valid is False
        assert reason == "User not authorized to use this token"
    
    def test_approve_request_success(self):
        """Test successful request approval"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Approve the request
        decision = self.approval_gate.approve_request(
            token=approval_request.token,
            user_id=self.test_user_id,
            approved=True
        )
        
        assert decision.token == approval_request.token
        assert decision.approved is True
        assert decision.decided_by == self.test_user_id
        assert decision.correlation_id == approval_request.correlation_id
        assert isinstance(decision.decided_at, datetime)
        
        # Verify decision is stored
        assert approval_request.token in self.approval_gate._approval_decisions
    
    def test_approve_request_denial(self):
        """Test request denial"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Deny the request
        decision = self.approval_gate.approve_request(
            token=approval_request.token,
            user_id=self.test_user_id,
            approved=False
        )
        
        assert decision.approved is False
    
    def test_approve_request_invalid_token(self):
        """Test approving invalid token"""
        with pytest.raises(ValueError, match="Invalid or unknown token"):
            self.approval_gate.approve_request(
                token="invalid_token",
                user_id=self.test_user_id,
                approved=True
            )
    
    def test_approve_request_expired_token(self):
        """Test approving expired token"""
        # Create approval request with past expiry
        with patch('src.approval_gate.datetime') as mock_datetime:
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            approval_request = self.approval_gate.create_approval_request(
                tool_call=self.test_tool_call,
                requested_by=self.test_user_id,
                expiry_minutes=15
            )
        
        # Try to approve with current time
        with pytest.raises(ValueError, match="Token has expired"):
            self.approval_gate.approve_request(
                token=approval_request.token,
                user_id=self.test_user_id,
                approved=True
            )
    
    def test_approve_request_unauthorized_user(self):
        """Test approving request with unauthorized user"""
        # Create approval request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Try to approve with different user
        with pytest.raises(ValueError, match="User not authorized to approve"):
            self.approval_gate.approve_request(
                token=approval_request.token,
                user_id="different_user",
                approved=True
            )
    
    def test_consume_approval_token_success(self):
        """Test successful token consumption"""
        # Create and approve request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        self.approval_gate.approve_request(approval_request.token, self.test_user_id, True)
        
        # Consume token
        result = self.approval_gate.consume_approval_token(approval_request.token)
        
        assert result is True
        assert approval_request.token in self.approval_gate._used_tokens
    
    def test_consume_approval_token_already_used(self):
        """Test consuming already used token"""
        # Create, approve, and consume request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        self.approval_gate.approve_request(approval_request.token, self.test_user_id, True)
        self.approval_gate.consume_approval_token(approval_request.token)
        
        # Try to consume again
        result = self.approval_gate.consume_approval_token(approval_request.token)
        
        assert result is False
    
    def test_consume_approval_token_invalid_token(self):
        """Test consuming invalid token"""
        result = self.approval_gate.consume_approval_token("invalid_token")
        assert result is False
    
    def test_consume_approval_token_not_approved(self):
        """Test consuming token that wasn't approved"""
        # Create but don't approve request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Try to consume without approval
        result = self.approval_gate.consume_approval_token(approval_request.token)
        assert result is False
    
    def test_consume_approval_token_denied(self):
        """Test consuming denied token"""
        # Create and deny request
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        self.approval_gate.approve_request(approval_request.token, self.test_user_id, False)
        
        # Try to consume denied token
        result = self.approval_gate.consume_approval_token(approval_request.token)
        assert result is False
    
    def test_format_approval_request_for_chat(self):
        """Test formatting approval request for chat display"""
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id,
            risk_level="high"
        )
        
        formatted = self.approval_gate.format_approval_request_for_chat(
            approval_request=approval_request,
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        assert formatted["type"] == "approval_request"
        assert formatted["token"] == approval_request.token
        assert formatted["title"] == "Approval Required: ec2_reboot"
        assert "SIMULATE (dry-run)" in formatted["description"]
        assert "instance_id: i-1234567890abcdef0" in formatted["description"]
        assert formatted["risk_level"] == "high"
        assert "🔴" in formatted["description"]  # High risk emoji
        assert formatted["execution_mode"] == "DRY_RUN"
        
        # Check actions
        assert len(formatted["actions"]) == 2
        approve_action = next(a for a in formatted["actions"] if a["type"] == "approve")
        deny_action = next(a for a in formatted["actions"] if a["type"] == "deny")
        
        assert "✅ Approve SIMULATE (dry-run)" in approve_action["label"]
        assert "❌ Deny" in deny_action["label"]
        assert approve_action["token"] == approval_request.token
        assert deny_action["token"] == approval_request.token
    
    def test_format_approval_request_different_modes(self):
        """Test formatting approval request for different execution modes"""
        approval_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id
        )
        
        # Test LOCAL_MOCK mode
        formatted_mock = self.approval_gate.format_approval_request_for_chat(
            approval_request=approval_request,
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        assert "SIMULATE" in formatted_mock["description"]
        assert "✅ Approve SIMULATE" in formatted_mock["actions"][0]["label"]
        
        # Test SANDBOX_LIVE mode
        formatted_live = self.approval_gate.format_approval_request_for_chat(
            approval_request=approval_request,
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        assert "EXECUTE" in formatted_live["description"]
        assert "✅ Approve EXECUTE" in formatted_live["actions"][0]["label"]
    
    def test_format_approval_request_no_tool_call(self):
        """Test formatting approval request without tool call"""
        approval_request = ApprovalRequest(
            requested_by=self.test_user_id,
            tool_call=None
        )
        
        with pytest.raises(ValueError, match="Approval request missing tool call"):
            self.approval_gate.format_approval_request_for_chat(approval_request)
    
    def test_cleanup_expired_tokens(self):
        """Test cleaning up expired tokens"""
        # Create some approval requests with different expiry times
        with patch('src.approval_gate.datetime') as mock_datetime:
            # Create expired request
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            expired_request = self.approval_gate.create_approval_request(
                tool_call=self.test_tool_call,
                requested_by=self.test_user_id,
                expiry_minutes=15
            )
            
            # Create decision for expired request
            self.approval_gate._approval_decisions[expired_request.token] = ApprovalDecision(
                token=expired_request.token,
                approved=True,
                decided_by=self.test_user_id
            )
        
        # Create valid request (with current time)
        valid_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by=self.test_user_id,
            expiry_minutes=15
        )
        
        # Verify both requests exist
        assert len(self.approval_gate._pending_approvals) == 2
        assert len(self.approval_gate._approval_decisions) == 1
        
        # Clean up expired tokens
        cleaned_count = self.approval_gate.cleanup_expired_tokens()
        
        assert cleaned_count == 1
        assert len(self.approval_gate._pending_approvals) == 1
        assert len(self.approval_gate._approval_decisions) == 0
        assert valid_request.token in self.approval_gate._pending_approvals
        assert expired_request.token not in self.approval_gate._pending_approvals
    
    def test_get_pending_approvals(self):
        """Test getting pending approvals for a user"""
        # Create multiple requests for different users
        user1_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by="user1"
        )
        
        user2_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by="user2"
        )
        
        # Create expired request for user1
        with patch('src.approval_gate.datetime') as mock_datetime:
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            expired_request = self.approval_gate.create_approval_request(
                tool_call=self.test_tool_call,
                requested_by="user1",
                expiry_minutes=15
            )
        
        # Create used token for user1
        used_request = self.approval_gate.create_approval_request(
            tool_call=self.test_tool_call,
            requested_by="user1"
        )
        self.approval_gate._used_tokens.add(used_request.token)
        
        # Get pending approvals for user1
        pending_user1 = self.approval_gate.get_pending_approvals("user1")
        
        assert len(pending_user1) == 1
        assert pending_user1[0].token == user1_request.token
        
        # Get pending approvals for user2
        pending_user2 = self.approval_gate.get_pending_approvals("user2")
        
        assert len(pending_user2) == 1
        assert pending_user2[0].token == user2_request.token
        
        # Get pending approvals for non-existent user
        pending_none = self.approval_gate.get_pending_approvals("nonexistent")
        assert len(pending_none) == 0
    
    def test_tool_calls_match_exact_match(self):
        """Test tool call matching with exact match"""
        tool_call1 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            correlation_id="test-correlation-id"
        )
        
        tool_call2 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            correlation_id="test-correlation-id"
        )
        
        result = self.approval_gate._tool_calls_match(tool_call1, tool_call2)
        assert result is True
    
    def test_tool_calls_match_different_tool_name(self):
        """Test tool call matching with different tool names"""
        tool_call1 = ToolCall(tool_name="ec2_reboot", correlation_id="test-id")
        tool_call2 = ToolCall(tool_name="ec2_stop", correlation_id="test-id")
        
        result = self.approval_gate._tool_calls_match(tool_call1, tool_call2)
        assert result is False
    
    def test_tool_calls_match_different_args(self):
        """Test tool call matching with different arguments"""
        tool_call1 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            correlation_id="test-id"
        )
        tool_call2 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-456"},
            correlation_id="test-id"
        )
        
        result = self.approval_gate._tool_calls_match(tool_call1, tool_call2)
        assert result is False
    
    def test_tool_calls_match_different_correlation_id(self):
        """Test tool call matching with different correlation IDs"""
        tool_call1 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            correlation_id="test-id-1"
        )
        tool_call2 = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            correlation_id="test-id-2"
        )
        
        result = self.approval_gate._tool_calls_match(tool_call1, tool_call2)
        assert result is False
    
    def test_unsupported_storage_backend(self):
        """Test initialization with unsupported storage backend"""
        with pytest.raises(ValueError, match="Unknown storage backend"):
            gate = ApprovalGate(storage_backend="redis")
            gate._store_approval_request(ApprovalRequest())
    
    def test_dynamodb_not_implemented(self):
        """Test that DynamoDB backend raises NotImplementedError"""
        gate = ApprovalGate(storage_backend="dynamodb")
        
        with pytest.raises(NotImplementedError, match="DynamoDB storage not yet implemented"):
            gate._store_approval_request(ApprovalRequest())
        
        with pytest.raises(NotImplementedError, match="DynamoDB storage not yet implemented"):
            gate._get_approval_request("test_token")


class TestApprovalDecision:
    """Test ApprovalDecision class"""
    
    def test_approval_decision_creation(self):
        """Test creating ApprovalDecision"""
        decision = ApprovalDecision(
            token="test_token",
            approved=True,
            decided_by="user123"
        )
        
        assert decision.token == "test_token"
        assert decision.approved is True
        assert decision.decided_by == "user123"
        assert isinstance(decision.decided_at, datetime)
        assert decision.correlation_id is not None
    
    def test_approval_decision_to_dict(self):
        """Test converting ApprovalDecision to dictionary"""
        decision = ApprovalDecision(
            token="test_token",
            approved=False,
            decided_by="user123"
        )
        
        data = decision.to_dict()
        
        assert data["token"] == "test_token"
        assert data["approved"] is False
        assert data["decided_by"] == "user123"
        assert "decided_at" in data
        assert "correlation_id" in data