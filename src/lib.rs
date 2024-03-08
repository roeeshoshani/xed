use core::{ffi::CStr, ptr::NonNull, sync::atomic::AtomicBool};

use arrayvec::ArrayVec;
use thiserror_no_std::Error;
use xed_sys2::{
    xed_absbr, xed_addr, xed_convert_to_encoder_request, xed_decode, xed_decoded_inst_get_base_reg,
    xed_decoded_inst_get_branch_displacement, xed_decoded_inst_get_branch_displacement_width_bits,
    xed_decoded_inst_get_category, xed_decoded_inst_get_iclass,
    xed_decoded_inst_get_immediate_is_signed, xed_decoded_inst_get_immediate_width_bits,
    xed_decoded_inst_get_index_reg, xed_decoded_inst_get_length,
    xed_decoded_inst_get_memop_address_width, xed_decoded_inst_get_memory_displacement,
    xed_decoded_inst_get_memory_displacement_width_bits, xed_decoded_inst_get_operand_width,
    xed_decoded_inst_get_reg, xed_decoded_inst_get_scale, xed_decoded_inst_get_signed_immediate,
    xed_decoded_inst_get_unsigned_immediate, xed_decoded_inst_inst, xed_decoded_inst_noperands,
    xed_decoded_inst_operand_length_bits, xed_decoded_inst_operands_const, xed_decoded_inst_t,
    xed_decoded_inst_valid, xed_decoded_inst_zero_set_mode, xed_disp, xed_encode,
    xed_encoder_instruction_t, xed_encoder_operand_t, xed_encoder_request_t,
    xed_encoder_request_zero_set_mode, xed_error_enum_t, xed_error_enum_t2str,
    xed_get_largest_enclosing_register, xed_get_largest_enclosing_register32,
    xed_get_register_width_bits, xed_get_register_width_bits64, xed_imm0, xed_inst,
    xed_inst_operand, xed_mem_gbisd, xed_operand_is_register, xed_operand_name,
    xed_operand_operand_visibility, xed_operand_values_has_segment_prefix,
    xed_operand_values_segment_prefix, xed_ptr, xed_reg, xed_reg_class,
    xed_register_abort_function, xed_relbr, xed_simm0, xed_state_get_address_width,
    xed_state_get_machine_mode, xed_state_get_stack_address_width, xed_state_init2, xed_state_t,
    xed_state_zero, xed_tables_init, XED_ENCODE_ORDER_MAX_OPERANDS,
};

pub use xed_sys2::XED_MAX_INSTRUCTION_BYTES;

static XED_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub const MAX_OPERANDS: usize = XED_ENCODE_ORDER_MAX_OPERANDS as usize;
pub const MAX_INSN_BYTES: usize = XED_MAX_INSTRUCTION_BYTES as usize;

fn init_xed_if_not_initialized() {
    unsafe {
        if !XED_INITIALIZED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            xed_tables_init();
            xed_register_abort_function(Some(xed_abort), core::ptr::null_mut())
        }
    }
}

unsafe extern "C" fn xed_abort(
    raw_msg: *const i8,
    raw_file: *const i8,
    line: i32,
    _: *mut core::ffi::c_void,
) {
    let msg = lossy_decode_xed_cstr(raw_msg);
    let file = lossy_decode_xed_cstr(raw_file);
    panic!("xed error ({}:{}): {}", file, line, msg);
}

/// lossily decode a xed cstr pointer, returning placeholder strings in case the cstring is not a valid utf-8 string.
/// the returned string is returned with a static lifetime to allow us to use literal strings for the placeholder strings,
/// but you must make sure to only use it while the provided pointer is valid.
unsafe fn lossy_decode_xed_cstr(cstr: *const i8) -> &'static str {
    match NonNull::new(cstr.cast_mut()) {
        Some(raw_msg_ptr) => CStr::from_ptr(raw_msg_ptr.as_ptr())
            .to_str()
            .unwrap_or("<non utf-8>"),
        None => "<null>",
    }
}

pub type XedMachineMode = xed_sys2::xed_machine_mode_enum_t;
pub type XedAddressWidth = xed_sys2::xed_address_width_enum_t;
pub type XedInsnCategory = xed_sys2::xed_category_enum_t;
pub type XedInsnIClass = xed_sys2::xed_iclass_enum_t;
pub type XedInsnExtension = xed_sys2::xed_extension_enum_t;
pub type XedOperandName = xed_sys2::xed_operand_enum_t;
pub type XedOperandVisibility = xed_sys2::xed_operand_visibility_enum_t;
pub type XedOperandType = xed_sys2::xed_operand_type_enum_t;
pub type XedOperandXType = xed_sys2::xed_operand_element_xtype_enum_t;
pub type XedOperandElementType = xed_sys2::xed_operand_element_type_enum_t;
pub type XedOperandAction = xed_sys2::xed_operand_action_enum_t;
pub type XedOperandWidth = xed_sys2::xed_operand_width_enum_t;
pub type Reg = xed_sys2::xed_reg_enum_t;
pub type RegClass = xed_sys2::xed_reg_class_enum_t;

#[derive(Clone)]
pub struct XedState {
    raw: xed_state_t,
}
impl XedState {
    pub fn new(machine_mode: XedMachineMode, stack_address_width: XedAddressWidth) -> Self {
        let mut result = Self {
            raw: unsafe { core::mem::zeroed() },
        };
        init_xed_if_not_initialized();
        unsafe { xed_state_zero(&mut result.raw) }
        unsafe { xed_state_init2(&mut result.raw, machine_mode, stack_address_width) };
        result
    }

    pub fn address_width(&self) -> XedAddressWidth {
        unsafe { xed_state_get_address_width(&self.raw) }
    }

    pub fn stack_address_width(&self) -> XedAddressWidth {
        unsafe { xed_state_get_stack_address_width(&self.raw) }
    }

    pub fn machine_mode(&self) -> XedMachineMode {
        unsafe { xed_state_get_machine_mode(&self.raw) }
    }

    pub fn decode(&self, buf: &[u8]) -> Result<DecodedInsn> {
        let mut decoded = unsafe { core::mem::zeroed::<xed_decoded_inst_t>() };
        unsafe { xed_decoded_inst_zero_set_mode(&mut decoded, &self.raw) }
        check_xed_result(unsafe {
            xed_decode(&mut decoded, buf.as_ptr().cast(), buf.len() as u32)
        })?;
        let is_valid = unsafe { xed_decoded_inst_valid(&decoded) };
        if is_valid == 0 {
            return Err(Error::DecodedInsnIsInvalid);
        }
        let mut operands = Operands::new();
        let num_of_operands = unsafe { xed_decoded_inst_noperands(&decoded) };
        let raw_inst = unsafe { xed_decoded_inst_inst(&decoded) };
        let raw_operands = unsafe { xed_decoded_inst_operands_const(&decoded) };
        let mut cur_mem_operands = 0;
        for op_idx in 0..num_of_operands {
            let operand = unsafe { xed_inst_operand(raw_inst, op_idx) };
            let vis = unsafe { xed_operand_operand_visibility(operand) };
            if vis != XedOperandVisibility::XED_OPVIS_EXPLICIT
                && vis != XedOperandVisibility::XED_OPVIS_IMPLICIT
            {
                continue;
            }
            let name = unsafe { xed_operand_name(operand) };
            if unsafe { xed_operand_is_register(name) } != 0 {
                operands.push(Operand::Reg(unsafe {
                    xed_decoded_inst_get_reg(&decoded, name)
                }))
            } else if name == XedOperandName::XED_OPERAND_MEM0
                || name == XedOperandName::XED_OPERAND_MEM1
                || name == XedOperandName::XED_OPERAND_AGEN
            {
                let displacement =
                    unsafe { xed_decoded_inst_get_memory_displacement(&decoded, cur_mem_operands) };
                operands.push(Operand::Mem(MemOperand {
                    base: reg_to_opt(unsafe {
                        xed_decoded_inst_get_base_reg(&decoded, cur_mem_operands)
                    }),
                    width_in_bits: unsafe {
                        xed_decoded_inst_operand_length_bits(&decoded, op_idx)
                    },
                    seg: if unsafe { xed_operand_values_has_segment_prefix(raw_operands) != 0 } {
                        reg_to_opt(unsafe { xed_operand_values_segment_prefix(raw_operands) })
                    } else {
                        None
                    },
                    sib: reg_to_opt(unsafe {
                        xed_decoded_inst_get_index_reg(&decoded, cur_mem_operands)
                    })
                    .map(|index_reg| MemOperandSib {
                        scale: unsafe { xed_decoded_inst_get_scale(&decoded, cur_mem_operands) },
                        index: index_reg,
                    }),
                    displacement: if displacement != 0 {
                        Some(MemOperandDisplacement {
                            displacement,
                            width_in_bits: unsafe {
                                xed_decoded_inst_get_memory_displacement_width_bits(
                                    &decoded,
                                    cur_mem_operands,
                                )
                            },
                        })
                    } else {
                        None
                    },
                    address_width_in_bits: unsafe {
                        xed_decoded_inst_get_memop_address_width(&decoded, cur_mem_operands)
                    },
                }));
                cur_mem_operands += 1;
            } else if name == XedOperandName::XED_OPERAND_IMM0
                || name == XedOperandName::XED_OPERAND_IMM0SIGNED
            {
                let is_signed = unsafe { xed_decoded_inst_get_immediate_is_signed(&decoded) };
                operands.push(Operand::Imm(ImmOperand {
                    value: if is_signed != 0 {
                        ImmValue::Signed(unsafe { xed_decoded_inst_get_signed_immediate(&decoded) })
                    } else {
                        ImmValue::Unsigned(unsafe {
                            xed_decoded_inst_get_unsigned_immediate(&decoded)
                        })
                    },
                    width_in_bits: unsafe { xed_decoded_inst_get_immediate_width_bits(&decoded) },
                }))
            } else if name == XedOperandName::XED_OPERAND_RELBR {
                let disp = unsafe { xed_decoded_inst_get_branch_displacement(&decoded) };
                let width =
                    unsafe { xed_decoded_inst_get_branch_displacement_width_bits(&decoded) };
                operands.push(Operand::BranchDisp(BranchDisp {
                    is_relative: true,
                    disp: disp as i32,
                    width_in_bits: width,
                }));
            } else if name == XedOperandName::XED_OPERAND_ABSBR {
                let disp = unsafe { xed_decoded_inst_get_branch_displacement(&decoded) };
                let width =
                    unsafe { xed_decoded_inst_get_branch_displacement_width_bits(&decoded) };
                operands.push(Operand::BranchDisp(BranchDisp {
                    is_relative: false,
                    disp: disp as i32,
                    width_in_bits: width,
                }));
            } else {
                return Err(Error::UnsupportedOperandNameDuringDecode(name));
            }
        }
        Ok(DecodedInsn {
            insn: Insn {
                iclass: unsafe { xed_decoded_inst_get_iclass(&decoded) },
                effective_operand_width_in_bits: unsafe {
                    xed_decoded_inst_get_operand_width(&decoded)
                },
                operands,
            },
            len: unsafe { xed_decoded_inst_get_length(&decoded) as usize },
            category: unsafe { xed_decoded_inst_get_category(&decoded) },
        })
    }

    pub fn decode_iter<'a>(&self, buf: &'a [u8]) -> DecodeIter<'a> {
        DecodeIter {
            bytes: buf,
            state: self.clone(),
            index: 0,
        }
    }

    pub fn encode(&self, insn: &Insn) -> Result<InsnBytes> {
        let mut raw_operands: ArrayVec<xed_encoder_operand_t, MAX_OPERANDS> = ArrayVec::new();
        for operand in &insn.operands {
            raw_operands.push(self.encode_operand(operand));
        }
        let mut encoder_inst = unsafe { core::mem::zeroed::<xed_encoder_instruction_t>() };
        let state = xed_state_t {
            mmode: self.machine_mode(),
            stack_addr_width: self.stack_address_width(),
        };
        unsafe {
            xed_inst(
                &mut encoder_inst,
                state,
                insn.iclass,
                insn.effective_operand_width_in_bits,
                raw_operands.len() as u32,
                raw_operands.as_ptr(),
            )
        }
        if let Some(mem_op) = insn.operands.iter().find_map(|op| match op {
            Operand::Mem(mem_op) => Some(mem_op),
            _ => None,
        }) {
            unsafe { xed_addr(&mut encoder_inst, mem_op.address_width_in_bits) }
        }
        let mut req = unsafe { core::mem::zeroed::<xed_encoder_request_t>() };
        unsafe { xed_encoder_request_zero_set_mode(&mut req, &encoder_inst.mode) }
        let convert_result = unsafe { xed_convert_to_encoder_request(&mut req, &mut encoder_inst) };
        if convert_result == 0 {
            return Err(Error::FailedToInsnToEncReq);
        }
        let mut insn_bytes = InsnBytes::new();
        let mut encoded_len = 0;
        check_xed_result(unsafe {
            xed_encode(
                &mut req,
                insn_bytes.as_mut_ptr(),
                XED_MAX_INSTRUCTION_BYTES,
                &mut encoded_len,
            )
        })?;
        unsafe { insn_bytes.set_len(encoded_len as usize) };
        if insn.iclass == XedInsnIClass::XED_ICLASS_XCHG {
            // xed adds an unneccessary lock prefix to XCHG instructions
            insn_bytes.remove(0);
        }
        Ok(insn_bytes)
    }

    fn encode_operand(&self, operand: &Operand) -> xed_encoder_operand_t {
        match operand {
            Operand::BranchDisp(branch_disp) => {
                if branch_disp.is_relative {
                    unsafe { xed_relbr(branch_disp.disp, branch_disp.width_in_bits) }
                } else {
                    unsafe { xed_absbr(branch_disp.disp, branch_disp.width_in_bits) }
                }
            }
            Operand::PtrDisp(ptr_disp) => unsafe { xed_ptr(ptr_disp.disp, ptr_disp.width_in_bits) },
            Operand::Reg(reg) => unsafe { xed_reg(*reg) },
            Operand::Imm(imm) => match imm.value {
                ImmValue::Signed(signed_imm) => unsafe { xed_simm0(signed_imm, imm.width_in_bits) },
                ImmValue::Unsigned(unsigned_imm) => unsafe {
                    xed_imm0(unsigned_imm, imm.width_in_bits)
                },
            },
            Operand::Mem(mem) => unsafe {
                xed_mem_gbisd(
                    opt_to_reg(mem.seg),
                    opt_to_reg(mem.base),
                    opt_to_reg(mem.sib.as_ref().map(|sib| sib.index)),
                    mem.sib.as_ref().map(|sib| sib.scale).unwrap_or(0),
                    match &mem.displacement {
                        Some(displacement) => {
                            xed_disp(displacement.displacement, displacement.width_in_bits)
                        }
                        None => xed_disp(0, 0),
                    },
                    mem.width_in_bits,
                )
            },
        }
    }
    pub fn reg_largest_enclosing(&self, reg: Reg) -> Reg {
        match self.machine_mode() {
            xed_sys2::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_64 => unsafe {
                xed_get_largest_enclosing_register(reg)
            },
            _ => unsafe { xed_get_largest_enclosing_register32(reg) },
        }
    }
    pub fn reg_start_bit_index_in_largest_enclosing(&self, reg: Reg) -> u32 {
        match reg {
            Reg::XED_REG_AH | Reg::XED_REG_BH | Reg::XED_REG_CH | Reg::XED_REG_DH => 8,
            _ => 0,
        }
    }
    pub fn reg_width_in_bits(&self, reg: Reg) -> u32 {
        match self.machine_mode() {
            xed_sys2::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_64 => unsafe {
                xed_get_register_width_bits64(reg)
            },
            _ => unsafe { xed_get_register_width_bits(reg) },
        }
    }
}

pub fn reg_class(reg: Reg) -> RegClass {
    unsafe { xed_reg_class(reg) }
}

#[derive(Clone)]
pub struct DecodeIter<'a> {
    index: usize,
    bytes: &'a [u8],
    state: XedState,
}
impl<'a> Iterator for DecodeIter<'a> {
    type Item = Result<DecodedIterInsn>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.bytes.len() {
            return None;
        }
        let result = self.state.decode(&self.bytes[self.index..]);
        let insn_index = self.index;
        if let Ok(decoded_insn) = &result {
            self.index += decoded_insn.len;
        }
        Some(result.map(|decoded_insn| DecodedIterInsn {
            decoded_insn,
            index_in_buffer: insn_index,
        }))
    }
}

fn reg_to_opt(reg: Reg) -> Option<Reg> {
    if reg == Reg::XED_REG_INVALID {
        None
    } else {
        Some(reg)
    }
}

fn opt_to_reg(opt: Option<Reg>) -> Reg {
    opt.unwrap_or(Reg::XED_REG_INVALID)
}

pub type InsnBytes = ArrayVec<u8, MAX_INSN_BYTES>;

fn check_xed_result(result: xed_error_enum_t) -> Result<()> {
    if result == xed_error_enum_t::XED_ERROR_NONE {
        Ok(())
    } else {
        Err(Error::RawXedError(RawXedError {
            code: result,
            message: unsafe { lossy_decode_xed_cstr(xed_error_enum_t2str(result)) },
        }))
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("raw xed error: {0}")]
    RawXedError(RawXedError),

    #[error("operand is null")]
    OperandIsNull,

    #[error(
        "operand index {index} is out of bounds for instruction with {operands_amount} operands"
    )]
    OperandIndexOutOfBounds {
        index: usize,
        operands_amount: usize,
    },

    #[error("decoded instruction is invalid")]
    DecodedInsnIsInvalid,

    #[error("failed to convert instruction to encoder request")]
    FailedToInsnToEncReq,

    #[error("unsupported raw operand name {0:?} while decoding an instruction")]
    UnsupportedOperandNameDuringDecode(XedOperandName),
}

#[derive(Debug, Error)]
#[error("{code:?}: {message}")]
pub struct RawXedError {
    code: xed_error_enum_t,
    message: &'static str,
}

pub type Operands = ArrayVec<Operand, MAX_OPERANDS>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecodedIterInsn {
    /// the actual decoded instruction.
    pub decoded_insn: DecodedInsn,
    /// the index of the first byte of this instruction in the decoded buffer.
    pub index_in_buffer: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecodedInsn {
    pub insn: Insn,
    pub len: usize,
    pub category: XedInsnCategory,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Insn {
    pub iclass: XedInsnIClass,
    pub effective_operand_width_in_bits: u32,
    pub operands: Operands,
}
impl Insn {
    pub const NOP: Self = Insn {
        iclass: XedInsnIClass::XED_ICLASS_NOP,
        effective_operand_width_in_bits: 0,
        operands: Operands::new_const(),
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operand {
    BranchDisp(BranchDisp),
    PtrDisp(PtrDisp),
    Reg(Reg),
    Imm(ImmOperand),
    Mem(MemOperand),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BranchDisp {
    pub is_relative: bool,
    pub disp: i32,
    pub width_in_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PtrDisp {
    pub disp: i32,
    pub width_in_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImmOperand {
    pub value: ImmValue,
    pub width_in_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImmValue {
    Signed(i32),
    Unsigned(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemOperand {
    pub base: Option<Reg>,
    /// the width of the memory reference in bits
    pub width_in_bits: u32,
    pub seg: Option<Reg>,
    pub sib: Option<MemOperandSib>,
    pub displacement: Option<MemOperandDisplacement>,
    pub address_width_in_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemOperandSib {
    pub scale: u32,
    pub index: Reg,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemOperandDisplacement {
    pub displacement: i64,
    pub width_in_bits: u32,
}
