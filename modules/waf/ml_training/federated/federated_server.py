import io
import base64
import torch
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("federated_server")

app = FastAPI(title="bunyanx FL Aggregation Server")

# Global state
global_model_state: Dict[str, Any] = {}
gradient_buffer: List[Dict[str, Any]] = []
expected_clients = 2  # Wait for 2 clients before aggregation
current_round = 0

class GradientSubmission(BaseModel):
    client_id: str
    round: int
    serialized_gradients: str  # Base64 encoded PyTorch state dict of gradients

def serialize_tensors(state_dict) -> str:
    buffer = io.BytesIO()
    torch.save(state_dict, buffer)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def deserialize_tensors(serialized_str) -> Dict[str, torch.Tensor]:
    bytes_data = base64.b64decode(serialized_str.encode('utf-8'))
    buffer = io.BytesIO(bytes_data)
    return torch.load(buffer, map_location="cpu")

@app.get("/status")
def get_status():
    return {
        "status": "active",
        "current_round": current_round,
        "clients_submitted": len(gradient_buffer),
        "expected_clients": expected_clients
    }

@app.get("/model")
def get_global_model():
    """Returns the current global model weights."""
    if not global_model_state:
        # If no global model initialized, return empty
        return {"round": current_round, "model_weights": ""}
    
    serialized = serialize_tensors(global_model_state)
    return {
        "round": current_round,
        "model_weights": serialized
    }

@app.post("/submit_gradients")
def submit_gradients(submission: GradientSubmission):
    global current_round, global_model_state, gradient_buffer
    
    if submission.round != current_round:
        raise HTTPException(
            status_code=400,
            detail=f"Out of sync round: client round is {submission.round}, server round is {current_round}"
        )
        
    try:
        grads = deserialize_tensors(submission.serialized_gradients)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to deserialize gradients: {e}")
        
    gradient_buffer.append(grads)
    logger.info(f"Received gradients from client '{submission.client_id}' for round {submission.round}. Buffer: {len(gradient_buffer)}/{expected_clients}")
    
    # Check if we have enough gradients to aggregate
    if len(gradient_buffer) >= expected_clients:
        logger.info(f"Starting FedAvg aggregation for round {current_round}...")
        aggregate_gradients()
        gradient_buffer.clear()
        current_round += 1
        logger.info(f"Round advanced to {current_round}. Global model updated.")
        
    return {"status": "success", "round": submission.round, "buffer_count": len(gradient_buffer)}

def aggregate_gradients():
    global global_model_state, gradient_buffer
    
    if not gradient_buffer:
        return
        
    # FedAvg
    # g_agg = mean(g_clients)
    num_clients = len(gradient_buffer)
    keys = gradient_buffer[0].keys()
    
    agg_grads = {}
    for key in keys:
        tensors = [client_grads[key] for client_grads in gradient_buffer]
        agg_grads[key] = torch.stack(tensors).mean(dim=0)
        
    # Update global model using aggregated gradients (simple SGD step)
    lr = 0.1
    if not global_model_state:
        # Initialize global model state with the aggregate gradient structure (as zero weights initially)
        global_model_state = {key: torch.zeros_like(tensor) for key, tensor in agg_grads.items()}
        
    for key in global_model_state.keys():
        if key in agg_grads:
            global_model_state[key] -= lr * agg_grads[key]

@app.post("/initialize_model")
def initialize_model(model_weights: Dict[str, str]):
    """Helper endpoint to initialize server global weights from WAF NLP model."""
    global global_model_state
    try:
        global_model_state = deserialize_tensors(model_weights["weights"])
        logger.info("Global model weights initialized successfully.")
        return {"status": "initialized"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    import sys
    port = 8008
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    logger.info(f"Running Federated Server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
