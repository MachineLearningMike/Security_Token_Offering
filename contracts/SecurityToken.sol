// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/dataStore/DataStroeUpgradeable.sol";
//import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./interfaces/ISecurityToken.sol";


//contract SecurityToken is SecurityTokenStorage, ERC20, ReentrancyGuard, IERC1594, IERC1643, IERC1644, IERC1410 {
contract SecurityToken is ERC20Upgradeable, ISecurityToken {

    using SafeMathUpgradeable for uint256;

    uint8 internal constant PERMISSION_KEY = 1;
    uint8 internal constant TRANSFER_KEY = 2;
    uint8 internal constant MINT_KEY = 3;
    uint8 internal constant CHECKPOINT_KEY = 4;
    uint8 internal constant BURN_KEY = 5;
    uint8 internal constant DATA_KEY = 6;
    uint8 internal constant WALLET_KEY = 7;

    bytes32 internal constant INVESTORSKEY = 0xdf3a8dd24acdd05addfc6aeffef7574d2de3f844535ec91e8e0f3e45dba96731; //keccak256(abi.encodePacked("INVESTORS"))
    bytes32 internal constant TREASURY = 0xaae8817359f3dcb67d050f44f3e49f982e0359d90ca4b5f18569926304aaece6; //keccak256(abi.encodePacked("TREASURY_WALLET"))
    bytes32 internal constant LOCKED = "LOCKED";
    bytes32 internal constant UNLOCKED = "UNLOCKED";

    //////////////////////////
    /// Document datastructure
    //////////////////////////

    struct Document {
        bytes32 docHash; // Hash of the document
        uint256 lastModified; // Timestamp at which document details was last modified
        string uri; // URI of the document that exist off-chain
    }

    // Used to hold the semantic version data
    struct SemanticVersion {
        uint8 major;
        uint8 minor;
        uint8 patch;
    }

    // Struct for module data
    struct ModuleData {
        bytes32 name;
        address module;
        address moduleFactory;
        bool isArchived;
        uint8[] moduleTypes;
        uint256[] moduleIndexes;
        uint256 nameIndex;
        bytes32 label;
    }

    // Structures to maintain checkpoints of balances for governance / dividends
    struct Checkpoint {
        uint256 checkpointId;
        uint256 value;
    }

    //Naming scheme to match Ownable
    address internal _owner;
    address public tokenFactory;
    bool public initialized;

    // Address of the controller which is a delegated entity
    // set by the issuer/owner of the token
    address public controller;

    //IPolymathRegistry public polymathRegistry;
    //IModuleRegistry public moduleRegistry;
    //ISecurityTokenRegistry public securityTokenRegistry;
    IERC20Upgradeable public polyToken;
    //address public getterDelegate;
    // Address of the data store used to store shared data
    IDataStore public dataStore;

    uint256 public granularity;

    // Value of current checkpoint
    uint256 public currentCheckpointId;

    // off-chain data
    string public tokenDetails;

    // Used to permanently halt controller actions
    bool public controllerDisabled = false;

    // Used to temporarily halt all transactions
    bool public transfersFrozen;

    // Number of investors with non-zero balance
    uint256 public holderCount;

    // Variable which tells whether issuance is ON or OFF forever
    // Implementers need to implement one more function to reset the value of `issuance` variable
    // to false. That function is not a part of the standard (EIP-1594) as it is depend on the various factors
    // issuer, followed compliance rules etc. So issuers have the choice how they want to close the issuance.
    bool internal issuance = true;

    // Array use to store all the document name present in the contracts
    bytes32[] _docNames;

    // Times at which each checkpoint was created
    uint256[] checkpointTimes;

    SemanticVersion securityTokenVersion;

    // Records added modules - module list should be order agnostic!
    mapping(uint8 => address[]) modules;

    // Records information about the module
    mapping(address => ModuleData) modulesToData;

    // Records added module names - module list should be order agnostic!
    mapping(bytes32 => address[]) names;

    // Mapping of checkpoints that relate to total supply
    mapping (uint256 => uint256) checkpointTotalSupply;

    // Map each investor to a series of checkpoints
    mapping(address => Checkpoint[]) checkpointBalances;

    // mapping to store the documents details in the document
    mapping(bytes32 => Document) internal _documents;
    // mapping to store the document name indexes
    mapping(bytes32 => uint256) internal _docIndexes;
    // Mapping from (investor, partition, operator) to approved status
    mapping (address => mapping (bytes32 => mapping (address => bool))) partitionApprovals;

    // Emit at the time when module get added
    event ModuleAdded(
        uint8[] _types,
        bytes32 indexed _name,
        address indexed _moduleFactory,
        address _module,
        uint256 _moduleCost,
        uint256 _budget,
        bytes32 _label,
        bool _archived
    );
    // Emit when Module get upgraded from the securityToken
    event ModuleUpgraded(uint8[] _types, address _module);
    // Emit when the token details get updated
    event UpdateTokenDetails(string _oldDetails, string _newDetails);
    // Emit when the token name get updated
    event UpdateTokenName(string _oldName, string _newName);
    // Emit when the granularity get changed
    event GranularityChanged(uint256 _oldGranularity, uint256 _newGranularity);
    // Emit when is permanently frozen by the issuer
    event FreezeIssuance();
    // Emit when transfers are frozen or unfrozen
    event FreezeTransfers(bool _status);
    // Emit when new checkpoint created
    event CheckpointCreated(uint256 indexed _checkpointId, uint256 _investorLength);
    // Events to log controller actions
    event SetController(address indexed _oldController, address indexed _newController);
    //Event emit when the global treasury wallet address get changed
    event TreasuryWalletChanged(address _oldTreasuryWallet, address _newTreasuryWallet);
    event DisableController();
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TokenUpgraded(uint8 _major, uint8 _minor, uint8 _patch);

    // Emit when Module get archived from the securityToken
    event ModuleArchived(uint8[] _types, address _module); //Event emitted by the tokenLib.
    // Emit when Module get unarchived from the securityToken
    event ModuleUnarchived(uint8[] _types, address _module); //Event emitted by the tokenLib.
    // Emit when Module get removed from the securityToken
    event ModuleRemoved(uint8[] _types, address _module); //Event emitted by the tokenLib.
    // Emit when the budget allocated to a module is changed
    event ModuleBudgetChanged(uint8[] _moduleTypes, address _module, uint256 _oldBudget, uint256 _budget); //Event emitted by the tokenLib.


    /**
     * @notice Initialization function
     * @dev Expected to be called atomically with the proxy being created, by the owner of the token
     * @dev Can only be called once
     */
    function initialize() public initializer {
        //Expected to be called atomically with the proxy being created
        securityTokenVersion = SemanticVersion(3, 0, 0);
        updateFromRegistry();
        tokenFactory = msg.sender;
    }

    /**
     * @notice Checks if an address is a module of certain type
     * @param _module Address to check
     * @param _type type to check against
     */
    function isModule(address _module, uint8 _type) public view returns(bool) {
        if (modulesToData[_module].module != _module || modulesToData[_module].isArchived)
            return false;
        for (uint256 i = 0; i < modulesToData[_module].moduleTypes.length; i++) {
            if (modulesToData[_module].moduleTypes[i] == _type) {
                return true;
            }
        }
        return false;
    }

    // Require msg.sender to be the specified module type or the owner of the token
    function _onlyModuleOrOwner(uint8 _type) internal view {
        if (msg.sender != owner())
            require(isModule(msg.sender, _type));
    }

    function _isValidPartition(bytes32 _partition) internal pure {
        require(_partition == UNLOCKED, "Invalid partition");
    }

    function _isValidOperator(address _from, address _operator, bytes32 _partition) internal view {
        _isAuthorised(
            allowance(_from, _operator) == uint(-1) || partitionApprovals[_from][_partition][_operator]
        );
    }

    function _zeroAddressCheck(address _entity) internal pure {
        require(_entity != address(0), "Invalid address");
    }

    function _isValidTransfer(bool _isTransfer) internal pure {
        require(_isTransfer, "Transfer Invalid");
    }

    function _isValidRedeem(bool _isRedeem) internal pure {
        require(_isRedeem, "Invalid redeem");
    }

    function _isSignedByOwner(bool _signed) internal pure {
        require(_signed, "Owner did not sign");
    }

    function _isIssuanceAllowed() internal view {
        require(issuance, "Issuance frozen");
    }

    // Function to check whether the msg.sender is authorised or not
    function _onlyController() internal view {
        _isAuthorised(msg.sender == controller && isControllable());
    }

    function _isAuthorised(bool _authorised) internal pure {
        require(_authorised, "Not Authorised");
    }

    function _onlyOwner() internal view {
        require(isOwner());
    }

    function withdrawERC20(address _tokenContract, uint256 _value) external {
        _onlyOwner();
        IERC20Upgradeable token = IERC20Upgradeable(_tokenContract);
        require(token.transfer(owner(), _value));
    }

    function updateTokenDetails(string calldata _newTokenDetails) external {
        _onlyOwner();
        emit UpdateTokenDetails(tokenDetails, _newTokenDetails);
        tokenDetails = _newTokenDetails;
    }

    function changeGranularity(uint256 _granularity) external {
        _onlyOwner();
        require(_granularity != 0, "Invalid granularity");
        emit GranularityChanged(granularity, _granularity);
        granularity = _granularity;
    }

    function changeDataStore(address _dataStore) external {
        _onlyOwner();
        _zeroAddressCheck(_dataStore);
        dataStore = IDataStore(_dataStore);
    }

    function changeName(string calldata _name) external {
        _onlyOwner();
        require(bytes(_name).length > 0);
        emit UpdateTokenName(name, _name);
        name = _name;
    }

    function changeTreasuryWallet(address _wallet) external {
        _onlyOwner();
        _zeroAddressCheck(_wallet);
        emit TreasuryWalletChanged(dataStore.getAddress(TREASURY), _wallet);
        dataStore.setAddress(TREASURY, _wallet);
    }

    function _adjustInvestorCount(address _from, address _to, uint256 _value) internal {
        holderCount = TokenLib.adjustInvestorCount(holderCount, _from, _to, _value, balanceOf(_to), balanceOf(_from), dataStore);
    }

    /**
     * @notice freezes transfers
     */
    function freezeTransfers() external {
        _onlyOwner();
        require(!transfersFrozen);
        transfersFrozen = true;
        /*solium-disable-next-line security/no-block-members*/
        emit FreezeTransfers(true);
    }

    /**
     * @notice Unfreeze transfers
     */
    function unfreezeTransfers() external {
        _onlyOwner();
        require(transfersFrozen);
        transfersFrozen = false;
        /*solium-disable-next-line security/no-block-members*/
        emit FreezeTransfers(false);
    }

    /**
     * @notice Internal - adjusts token holder balance at checkpoint before a token transfer
     * @param _investor address of the token holder affected
     */
    function _adjustBalanceCheckpoints(address _investor) internal {
        TokenLib.adjustCheckpoints(checkpointBalances[_investor], balanceOf(_investor), currentCheckpointId);
    }


    function transfer(address _to, uint256 _value) public returns(bool success) {
        _transferWithData(msg.sender, _to, _value, "");
        return true;
    }

    function transferWithData(address _to, uint256 _value, bytes memory _data) public {
        _transferWithData(msg.sender, _to, _value, _data);
    }

    function _transferWithData(address _from, address _to, uint256 _value, bytes memory _data) internal {
        _isValidTransfer(_updateTransfer(_from, _to, _value, _data));
        // Using the internal function instead of super.transfer() in the favour of reducing the code size
        _transfer(_from, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        transferFromWithData(_from, _to, _value, "");
        return true;
    }

    function transferFromWithData(address _from, address _to, uint256 _value, bytes memory _data) public {
        _isValidTransfer(_updateTransfer(_from, _to, _value, _data));
        require(super.transferFrom(_from, _to, _value));
    }

    function balanceOfByPartition(bytes32 _partition, address _tokenHolder) public view returns(uint256) {
        return _balanceOfByPartition(_partition, _tokenHolder, 0);
    }

    function _balanceOfByPartition(bytes32 _partition, address _tokenHolder, uint256 _additionalBalance) internal view returns(uint256 partitionBalance) {
        address[] memory tms = modules[TRANSFER_KEY];
        uint256 amount;
        for (uint256 i = 0; i < tms.length; i++) {
            amount = ITransferManager(tms[i]).getTokensByPartition(_partition, _tokenHolder, _additionalBalance);
            // In UNLOCKED partition we are returning the minimum of all the unlocked balances
            if (_partition == UNLOCKED) {
                if (amount < partitionBalance || i == 0)
                    partitionBalance = amount;
            }
            // In locked partition we are returning the maximum of all the Locked balances
            else {
                if (partitionBalance < amount)
                    partitionBalance = amount;
            }
        }
    }

    function transferByPartition(bytes32 _partition, address _to, uint256 _value, bytes memory _data) public returns (bytes32) {
        return _transferByPartition(msg.sender, _to, _value, _partition, _data, address(0), "");
    }

    function _transferByPartition(
        address _from,
        address _to,
        uint256 _value,
        bytes32 _partition,
        bytes memory _data,
        address _operator,
        bytes memory _operatorData
    )
        internal
        returns(bytes32 toPartition)
    {
        _isValidPartition(_partition);
        // Avoiding to add this check
        // require(balanceOfByPartition(_partition, msg.sender) >= _value);
        // NB - Above condition will be automatically checked using the executeTransfer() function execution.
        // NB - passing `_additionalBalance` value is 0 because accessing the balance before transfer
        uint256 lockedBalanceBeforeTransfer = _balanceOfByPartition(LOCKED, _to, 0);
        _transferWithData(_from, _to, _value, _data);
        // NB - passing `_additonalBalance` valie is 0 because balance of `_to` was updated in the transfer call
        uint256 lockedBalanceAfterTransfer = _balanceOfByPartition(LOCKED, _to, 0);
        toPartition =  _returnPartition(lockedBalanceBeforeTransfer, lockedBalanceAfterTransfer, _value);
        emit TransferByPartition(_partition, _operator, _from, _to, _value, _data, _operatorData);
    }

    function _returnPartition(uint256 _beforeBalance, uint256 _afterBalance, uint256 _value) internal pure returns(bytes32 toPartition) {
        // return LOCKED only when the transaction `_value` should be equal to the change in the LOCKED partition
        // balance otherwise return UNLOCKED
        toPartition = _afterBalance.sub(_beforeBalance) == _value ? LOCKED : UNLOCKED; // Returning the same partition UNLOCKED
    }

    ///////////////////////
    /// Operator Management
    ///////////////////////

    function authorizeOperator(address _operator) public {
        _approve(msg.sender, _operator, uint(-1));
        emit AuthorizedOperator(_operator, msg.sender);
    }

    function revokeOperator(address _operator) public {
        _approve(msg.sender, _operator, 0);
        emit RevokedOperator(_operator, msg.sender);
    }

    function authorizeOperatorByPartition(bytes32 _partition, address _operator) public {
        _isValidPartition(_partition);
        partitionApprovals[msg.sender][_partition][_operator] = true;
        emit AuthorizedOperatorByPartition(_partition, _operator, msg.sender);
    }

    /**
     * @notice Revokes authorisation of an operator previously given for a specified partition of `msg.sender`
     * @param _partition The partition to which the operator is de-authorised
     * @param _operator An address which is being de-authorised
     */
    function revokeOperatorByPartition(bytes32 _partition, address _operator) public {
        _isValidPartition(_partition);
        partitionApprovals[msg.sender][_partition][_operator] = false;
        emit RevokedOperatorByPartition(_partition, _operator, msg.sender);
    }

    function operatorTransferByPartition(
        bytes32 _partition,
        address _from,
        address _to,
        uint256 _value,
        bytes calldata _data,
        bytes calldata _operatorData
    )
        external
        returns (bytes32)
    {
        // For the current release we are only allowing UNLOCKED partition tokens to transact
        _validateOperatorAndPartition(_partition, _from, msg.sender);
        require(_operatorData[0] != 0);
        return _transferByPartition(_from, _to, _value, _partition, _data, msg.sender, _operatorData);
    }

    function _validateOperatorAndPartition(bytes32 _partition, address _from, address _operator) internal view {
        _isValidPartition(_partition);
        _isValidOperator(_from, _operator, _partition);
    }

    function _updateTransfer(address _from, address _to, uint256 _value, bytes memory _data) internal 
    //nonReentrant 
    returns(bool verified) {
        // NB - the ordering in this function implies the following:
        //  - investor counts are updated before transfer managers are called - i.e. transfer managers will see
        //investor counts including the current transfer.
        //  - checkpoints are updated after the transfer managers are called. This allows TMs to create
        //checkpoints as though they have been created before the current transactions,
        //  - to avoid the situation where a transfer manager transfers tokens, and this function is called recursively,
        //the function is marked as nonReentrant. This means that no TM can transfer (or mint / burn) tokens in the execute transfer function.
        _adjustInvestorCount(_from, _to, _value);
        verified = _executeTransfer(_from, _to, _value, _data);
        _adjustBalanceCheckpoints(_from);
        _adjustBalanceCheckpoints(_to);
    }

    function _executeTransfer(
        address _from,
        address _to,
        uint256 _value,
        bytes memory _data
    )
        internal
        //checkGranularity(_value)
        returns(bool)
    {
        if (!transfersFrozen) {
            bool isInvalid;
            bool isValid;
            bool isForceValid;
            address module;
            uint256 tmLength = modules[TRANSFER_KEY].length;
            for (uint256 i = 0; i < tmLength; i++) {
                module = modules[TRANSFER_KEY][i];
                if (!modulesToData[module].isArchived) {
                    // refer to https://github.com/PolymathNetwork/polymath-core/wiki/Transfer-manager-results
                    // for understanding what these results mean
                    ITransferManager.Result valid = ITransferManager(module).executeTransfer(_from, _to, _value, _data);
                    if (valid == ITransferManager.Result.INVALID) {
                        isInvalid = true;
                    } else if (valid == ITransferManager.Result.VALID) {
                        isValid = true;
                    } else if (valid == ITransferManager.Result.FORCE_VALID) {
                        isForceValid = true;
                    }
                }
            }
            return isForceValid ? true : (isInvalid ? false : isValid);
        }
        return false;
    }

    function freezeIssuance(bytes calldata _signature) external {
        _onlyOwner();
        _isIssuanceAllowed();
        _isSignedByOwner(owner() == TokenLib.recoverFreezeIssuanceAckSigner(_signature));
        issuance = false;
        /*solium-disable-next-line security/no-block-members*/
        emit FreezeIssuance();
    }

    function issue(
        address _tokenHolder,
        uint256 _value,
        bytes memory _data
    )
        public // changed to public to save the code size and reuse the function
    {
        _isIssuanceAllowed();
        _onlyModuleOrOwner(MINT_KEY);
        _issue(_tokenHolder, _value, _data);
    }

    function _issue(
        address _tokenHolder,
        uint256 _value,
        bytes memory _data
    )
        internal
    {
        // Add a function to validate the `_data` parameter
        _isValidTransfer(_updateTransfer(address(0), _tokenHolder, _value, _data));
        _mint(_tokenHolder, _value);
        emit Issued(msg.sender, _tokenHolder, _value, _data);
    }

    function issueMulti(address[] memory _tokenHolders, uint256[] memory _values) public {
        _isIssuanceAllowed();
        _onlyModuleOrOwner(MINT_KEY);
        // Remove reason string to reduce the code size
        require(_tokenHolders.length == _values.length);
        for (uint256 i = 0; i < _tokenHolders.length; i++) {
            _issue(_tokenHolders[i], _values[i], "");
        }
    }

    function issueByPartition(bytes32 _partition, address _tokenHolder, uint256 _value, bytes calldata _data) external {
        _isValidPartition(_partition);
        //Use issue instead of _issue function in the favour to saving code size
        issue(_tokenHolder, _value, _data);
        emit IssuedByPartition(_partition, _tokenHolder, _value, _data);
    }

    function redeem(uint256 _value, bytes calldata _data) external {
        _onlyModule(BURN_KEY);
        _redeem(msg.sender, _value, _data);
    }

    function _redeem(address _from, uint256 _value, bytes memory _data) internal {
        // Add a function to validate the `_data` parameter
        _isValidRedeem(_checkAndBurn(_from, _value, _data));
    }

    function redeemByPartition(bytes32 _partition, uint256 _value, bytes calldata _data) external {
        _onlyModule(BURN_KEY);
        _isValidPartition(_partition);
        _redeemByPartition(_partition, msg.sender, _value, address(0), _data, "");
    }

    function _redeemByPartition(
        bytes32 _partition,
        address _from,
        uint256 _value,
        address _operator,
        bytes memory _data,
        bytes memory _operatorData
    )
        internal
    {
        _redeem(_from, _value, _data);
        emit RedeemedByPartition(_partition, _operator, _from, _value, _data, _operatorData);
    }

    function operatorRedeemByPartition(
        bytes32 _partition,
        address _tokenHolder,
        uint256 _value,
        bytes calldata _data,
        bytes calldata _operatorData
    )
        external
    {
        _onlyModule(BURN_KEY);
        require(_operatorData[0] != 0);
        _zeroAddressCheck(_tokenHolder);
        _validateOperatorAndPartition(_partition, _tokenHolder, msg.sender);
        _redeemByPartition(_partition, _tokenHolder, _value, msg.sender, _data, _operatorData);
    }

    function _checkAndBurn(address _from, uint256 _value, bytes memory _data) internal returns(bool verified) {
        verified = _updateTransfer(_from, address(0), _value, _data);
        _burn(_from, _value);
        emit Redeemed(address(0), msg.sender, _value, _data);
    }

    function redeemFrom(address _tokenHolder, uint256 _value, bytes calldata _data) external {
        _onlyModule(BURN_KEY);
        // Add a function to validate the `_data` parameter
        _isValidRedeem(_updateTransfer(_tokenHolder, address(0), _value, _data));
        _burnFrom(_tokenHolder, _value);
        emit Redeemed(msg.sender, _tokenHolder, _value, _data);
    }

    function createCheckpoint() external returns(uint256) {
        _onlyModuleOrOwner(CHECKPOINT_KEY);
        // currentCheckpointId can only be incremented by 1 and hence it can not be overflowed
        currentCheckpointId = currentCheckpointId + 1;
        /*solium-disable-next-line security/no-block-members*/
        checkpointTimes.push(now);
        checkpointTotalSupply[currentCheckpointId] = totalSupply();
        emit CheckpointCreated(currentCheckpointId, dataStore.getAddressArrayLength(INVESTORSKEY));
        return currentCheckpointId;
    }

    function setController(address _controller) external {
        _onlyOwner();
        require(isControllable());
        emit SetController(controller, _controller);
        controller = _controller;
    }

    function disableController(bytes calldata _signature) external {
        _onlyOwner();
        _isSignedByOwner(owner() == TokenLib.recoverDisableControllerAckSigner(_signature));
        require(isControllable());
        controllerDisabled = true;
        delete controller;
        emit DisableController();
    }

    function canTransfer(address _to, uint256 _value, bytes calldata _data) external view returns (bytes1, bytes32) {
        return _canTransfer(msg.sender, _to, _value, _data);
    }


    function canTransferFrom(address _from, address _to, uint256 _value, bytes calldata _data) external view returns (bytes1 reasonCode, bytes32 appCode) {
        (reasonCode, appCode) = _canTransfer(_from, _to, _value, _data);
        if (_isSuccess(reasonCode) && _value > allowance(_from, msg.sender)) {
            return (StatusCodes.code(StatusCodes.Status.InsufficientAllowance), bytes32(0));
        }
    }

    function _canTransfer(address _from, address _to, uint256 _value, bytes memory _data) internal view returns (bytes1, bytes32) {
        bytes32 appCode;
        bool success;
        if (_value % granularity != 0) {
            return (StatusCodes.code(StatusCodes.Status.TransferFailure), bytes32(0));
        }
        (success, appCode) = TokenLib.verifyTransfer(modules[TRANSFER_KEY], modulesToData, _from, _to, _value, _data, transfersFrozen);
        return TokenLib.canTransfer(success, appCode, _to, _value, balanceOf(_from));
    }


    function canTransferByPartition(
        address _from,
        address _to,
        bytes32 _partition,
        uint256 _value,
        bytes calldata _data
    )
        external
        view
        returns (bytes1 reasonCode, bytes32 appStatusCode, bytes32 toPartition)
    {
        if (_partition == UNLOCKED) {
            (reasonCode, appStatusCode) = _canTransfer(_from, _to, _value, _data);
            if (_isSuccess(reasonCode)) {
                uint256 beforeBalance = _balanceOfByPartition(LOCKED, _to, 0);
                uint256 afterbalance = _balanceOfByPartition(LOCKED, _to, _value);
                toPartition = _returnPartition(beforeBalance, afterbalance, _value);
            }
            return (reasonCode, appStatusCode, toPartition);
        }
        return (StatusCodes.code(StatusCodes.Status.TransferFailure), bytes32(0), bytes32(0));
    }

    function setDocument(bytes32 _name, string calldata _uri, bytes32 _documentHash) external {
        _onlyOwner();
        TokenLib.setDocument(_documents, _docNames, _docIndexes, _name, _uri, _documentHash);
    }

    function removeDocument(bytes32 _name) external {
        _onlyOwner();
        TokenLib.removeDocument(_documents, _docNames, _docIndexes, _name);
    }


    function isControllable() public view returns (bool) {
        return !controllerDisabled;
    }


    function controllerTransfer(address _from, address _to, uint256 _value, bytes calldata _data, bytes calldata _operatorData) external {
        _onlyController();
        _updateTransfer(_from, _to, _value, _data);
        _transfer(_from, _to, _value);
        emit ControllerTransfer(msg.sender, _from, _to, _value, _data, _operatorData);
    }


    function controllerRedeem(address _tokenHolder, uint256 _value, bytes calldata _data, bytes calldata _operatorData) external {
        _onlyController();
        _checkAndBurn(_tokenHolder, _value, _data);
        emit ControllerRedemption(msg.sender, _tokenHolder, _value, _data, _operatorData);
    }

    function _implementation() internal view returns(address) {
        return getterDelegate;
    }

    function updateFromRegistry() public {
        _onlyOwner();
        moduleRegistry = IModuleRegistry(polymathRegistry.getAddress("ModuleRegistry"));
        securityTokenRegistry = ISecurityTokenRegistry(polymathRegistry.getAddress("SecurityTokenRegistry"));
        polyToken = IERC20(polymathRegistry.getAddress("PolyToken"));
    }

    //Ownable Functions

    function owner() public view returns (address) {
        return _owner;
    }

    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }

    function transferOwnership(address newOwner) external {
        _onlyOwner();
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0));
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function _isSuccess(bytes1 status) internal pure returns (bool successful) {
        return (status & 0x0F) == 0x01;
    }

}
