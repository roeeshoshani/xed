use std::process::Command;

use arrayvec::ArrayVec;
use xed::{
    ImmOperand, ImmValue, Insn, MemOperand, MemOperandDisplacement, MemOperandSib, Operand, Reg,
    XedAddressWidth, XedInsnIClass, XedMachineMode, XedState, MAX_INSN_BYTES,
};

fn main() {
    decode_test()
    // encode_test()
    // raw_encode_test()
}

fn raw_encode_test() {
    let operands = unsafe {
        [
            xed_sys2::xed_reg(Reg::XED_REG_RAX),
            xed_sys2::xed_reg(Reg::XED_REG_RDI),
        ]
    };
    unsafe { xed_sys2::xed_tables_init() };
    let mut insn = unsafe { core::mem::zeroed::<xed_sys2::xed_encoder_instruction_t>() };
    let state = xed_sys2::xed_state_t {
        mmode: XedMachineMode::XED_MACHINE_MODE_LONG_64,
        stack_addr_width: XedAddressWidth::XED_ADDRESS_WIDTH_64b,
    };
    unsafe {
        xed_sys2::xed_inst(
            &mut insn,
            state,
            XedInsnIClass::XED_ICLASS_XOR,
            64,
            operands.len() as u32,
            operands.as_ptr(),
        )
    }
    let mut req = unsafe { core::mem::zeroed::<xed_sys2::xed_encoder_request_t>() };
    unsafe { xed_sys2::xed_encoder_request_zero_set_mode(&mut req, &insn.mode) };
    let convert_result = unsafe { xed_sys2::xed_convert_to_encoder_request(&mut req, &mut insn) };
    assert_ne!(convert_result, 0);
    let mut buf = [0u8; MAX_INSN_BYTES];
    let mut enc_len = 0;
    let encode_res =
        unsafe { xed_sys2::xed_encode(&mut req, buf.as_mut_ptr(), buf.len() as u32, &mut enc_len) };
    dbg!(encode_res);
    dbg!(&buf[..enc_len as usize]);
}

fn encode_test() {
    let xed_state = XedState::new(
        XedMachineMode::XED_MACHINE_MODE_LONG_64,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
    );
    let insn = Insn {
        iclass: XedInsnIClass::XED_ICLASS_ADD,
        effective_operand_width_in_bits: 64,
        operands: [
            Operand::Reg(Reg::XED_REG_RAX),
            Operand::Mem(MemOperand {
                base: None,
                width_in_bits: 64,
                seg: None,
                sib: None,
                displacement: Some(MemOperandDisplacement {
                    displacement: -5,
                    width_in_bits: 32,
                }),
                address_width_in_bits: 64,
            }),
        ]
        .into_iter()
        .collect(),
    };
    let result = xed_state.encode(&insn).unwrap();
    let output_file_path = "/tmp/.xed_enc_test";
    std::fs::write(output_file_path, result.as_slice()).unwrap();
    let exit_code = Command::new("objdump")
        .args("-Mintel -D -b binary -Mx86-64 -mi386:x86-64".split(' '))
        .arg(output_file_path)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(exit_code.success());
    let decoded = xed_state.decode(&result).unwrap();
    assert_eq!(decoded.insn, insn);
}

fn decode_test() {
    let stdin = std::io::stdin();
    let mut input = String::new();
    loop {
        input.clear();
        stdin.read_line(&mut input).unwrap();

        dump_operands(&input);
    }
}

fn dump_operands(assembly_line: &str) {
    let bytes = nasm_assemble(&format!("bits 64\n{}", assembly_line));
    let xed_state = XedState::new(
        XedMachineMode::XED_MACHINE_MODE_LONG_64,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
    );
    let decoded_insn = xed_state.decode(&bytes).unwrap();
    println!("{:#?}", decoded_insn);
    let encoded = xed_state.encode(&decoded_insn.insn).unwrap();
    assert_eq!(encoded.as_slice(), bytes.as_slice());
}

fn nasm_assemble(assembly_code: &str) -> Vec<u8> {
    let asm_file_path = "/tmp/.xed_example_basic_nasm.asm";
    let output_file_path = "/tmp/.xed_example_basic_nasm.bin";
    std::fs::write(asm_file_path, assembly_code.as_bytes()).unwrap();
    let exit_code = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg(asm_file_path)
        .arg("-o")
        .arg(output_file_path)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(exit_code.success());
    std::fs::read(output_file_path).unwrap()
}
