use cita_types::traits::LowerHex;
use cita_types::Address;
use evm::action_params::ActionParams;
use evm::env_info::EnvInfo;
use evm::error::Error as EvmError;
use grpc::Result as GrpcResult;
use grpc_contracts::contract_state::ConnectInfo;
use grpc_contracts::grpc_vm::CallEvmImpl;
use grpc_contracts::service_registry;
use libproto::citacode::{ InvokeRequest, InvokeResponse };
use state::backend::Backend as StateBackend;
use state::State;
use std::str::FromStr;
use types::reserved_addresses;

lazy_static! {
    static ref CONTRACT_CREATION_ADDRESS: Address =
        Address::from_str(reserved_addresses::GO_CONTRACT).unwrap();
    static ref LOW_CONTRACT_ADDRESS: Address =
        Address::from_str(reserved_addresses::GO_CONTRACT_MIN).unwrap();
    static ref HIGH_CONTRACT_ADDRESS: Address =
        Address::from_str(reserved_addresses::GO_CONTRACT_MAX).unwrap();
}

const MSG_EMPTY_DATA_FIELD: &'static str = "GRPC contract creation without data field";
const MSG_CONTRACT_ADDRESS_NOT_FOUND: &'static str = "can't find grpc contract from address";

pub struct GrpcContract<'a, B: 'a>
where
    B: StateBackend
{
    state: &'a mut State<B>,
    params: &'a ActionParams,

    address: Address,
    connect: ConnectInfo,
    request: InvokeRequest,
}

impl<'a, B> GrpcContract<'a, B>
where
    B: StateBackend + 'a
{
    pub fn new(
        env: &'a EnvInfo,
        params: &'a ActionParams,
        state: &'a mut State<B>,
    ) -> Result<GrpcContract<'a, B>, EvmError> {
        let address = Self::address(params)?;
        let connect = Self::connect_info(params)?;
        let request = Self::new_request(params, &connect, env);

        Ok(Self { params, state, address, connect, request })
    }

    pub fn invoke(self, check_permission: bool, _check_quote: bool) -> GrpcResult<InvokeResponse> {
        let mut evm_impl = CallEvmImpl::new(self.state, check_permission);
        let ip = self.connect.get_ip();
        let port = self.connect.get_port();

        if is_creation(self.params) {
            service_registry::enable_contract(self.address);
            evm_impl.create(ip, port, self.request)
        } else {
            evm_impl.call(ip, port, self.request)
        }
    }

    fn connect_info(params: &ActionParams) -> Result<ConnectInfo, EvmError> {
        let address = Self::address(params)?;

        service_registry::find_contract(address, !is_creation(params))
            .ok_or(EvmError::Internal(format!("{}: {:?}", MSG_CONTRACT_ADDRESS_NOT_FOUND, address)))
            .map(|contract_state| contract_state.conn_info)
    }

    fn address(params: &ActionParams) -> Result<Address, EvmError> {
        if is_creation(params) {
            params.data.clone()
                .ok_or(EvmError::Internal(String::from(MSG_EMPTY_DATA_FIELD)))
                .and_then(|data| Ok(Address::from_slice(&data)))
        } else {
            Ok(params.code_address)
        }
    }

    fn new_request(params: &ActionParams, connect: &ConnectInfo, env: &EnvInfo) -> InvokeRequest {
        use libproto::citacode::{ActionParams as ProtoActionParams, EnvInfo as ProtoEnvInfo };

        let mut proto_env_info = ProtoEnvInfo::new();
        proto_env_info.set_number(format!("{}", env.number));
        proto_env_info.set_author(Address::default().lower_hex());
        proto_env_info.set_timestamp(format!("{}", env.timestamp));

        let mut proto_params = ProtoActionParams::new();
        proto_params.set_code_address(connect.get_addr().to_string());
        proto_params.set_data(params.data.to_owned().unwrap());
        proto_params.set_sender(params.sender.lower_hex());

        let mut invoke_request = InvokeRequest::new();
        invoke_request.set_param(proto_params);
        invoke_request.set_env_info(proto_env_info.clone());

        invoke_request
    }
}

pub fn low_contract_address() -> Address {
    *LOW_CONTRACT_ADDRESS
}

pub fn high_contract_address() -> Address {
    *HIGH_CONTRACT_ADDRESS
}

pub fn contract_creation_address() -> Address {
    *CONTRACT_CREATION_ADDRESS
}

pub fn is_creation(params: &ActionParams) -> bool {
    params.code_address == *CONTRACT_CREATION_ADDRESS
}

pub fn is_validate(params: &ActionParams) -> bool {
    params.code_address >= *LOW_CONTRACT_ADDRESS && params.code_address <= *HIGH_CONTRACT_ADDRESS
}
