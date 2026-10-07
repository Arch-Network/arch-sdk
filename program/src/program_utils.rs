use crate::instruction::InstructionError;

pub fn deserialize_syscall_instruction<T>(instruction_data: &[u8]) -> Result<T, InstructionError>
where
    T: for<'de> wincode::Deserialize<'de, Dst = T>,
{
    wincode::deserialize(instruction_data).map_err(|_| InstructionError::InvalidInstructionData)
}
